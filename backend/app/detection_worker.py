"""Worker dedicado do detector de anomalias (PERF-C.0).

Mesmo codigo/imagem do backend, entrypoint diferente:

    python -m app.detection_worker

Responsabilidades:
- rodar `detect_anomalies_once()` em loop, fora do processo da API (sem GIL compartilhado);
- garantir UM UNICO dono do detector via lease em SQLite (`detection_worker_lease`);
- publicar o status no SQLite (`detection_runtime_state`) para `/api/detection/status`;
- expor `/health` e `/status` proprio (usado pelo healthcheck do container).

Este processo NAO sobe o FastAPI nem qualquer outro worker do backend.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app import main as backend

logger = logging.getLogger("gmj-flow-detector")
logging.basicConfig(level=os.getenv("GMJFLOW_DETECTOR_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")

OWNER = f"detector@{backend.detection_worker_identity()}"
STOP = threading.Event()
STATE: dict[str, object] = {
    "started_at": backend.utc_now_iso(),
    "owner": OWNER,
    "holding_lease": False,
    "cycles": 0,
    "last_cycle_started_at": "",
    "last_cycle_finished_at": "",
    "last_error": "",
    "status": {},
}


def _heartbeat_loop() -> None:
    ttl = backend.detection_lease_ttl_seconds()
    interval = max(5, ttl // 3)
    while not STOP.wait(interval):
        if not STATE["holding_lease"]:
            continue
        if not backend.detection_lease_renew(OWNER, ttl):
            STATE["holding_lease"] = False
            logger.warning("lease perdido para outro processo; tentando readquirir no proximo ciclo")


def _status_payload() -> dict[str, object]:
    lease = backend.detection_lease_info() or {}
    payload = dict(STATE)
    payload["lease"] = lease
    payload["interval_seconds"] = backend.detection_scheduler_interval_seconds()
    payload["anomaly_detection_enabled"] = backend.anomaly_detection_enabled()
    payload["worker_enabled"] = backend.detection_worker_enabled()
    payload["reconcile_enabled"] = backend.detection_reconcile_enabled()
    return payload


class _Handler(BaseHTTPRequestHandler):
    server_version = "gmj-flow-detector/1.0"

    def do_GET(self):  # noqa: N802 - assinatura do BaseHTTPRequestHandler
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path in ("/health", "/healthz"):
            healthy = bool(STATE["holding_lease"]) and not STOP.is_set()
            body = json.dumps({"ok": healthy, "owner": OWNER, "cycles": STATE["cycles"]})
            self._respond(200 if healthy else 503, body)
            return
        if path == "/status":
            self._respond(200, json.dumps(_status_payload(), default=str, sort_keys=True))
            return
        self._respond(404, json.dumps({"detail": "not found"}))

    def _respond(self, code: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):  # noqa: A002 - assinatura
        logger.debug("http %s", format % args)


def _start_http_server() -> ThreadingHTTPServer:
    port = backend.detection_worker_port()
    server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    thread = threading.Thread(target=server.serve_forever, name="gmj-flow-detector-http", daemon=True)
    thread.start()
    logger.info("worker http escutando na porta %s", port)
    return server


def _install_signal_handlers() -> None:
    def _stop(signum, frame):  # noqa: ARG001
        logger.info("sinal %s recebido; encerrando", signum)
        STOP.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):  # pragma: no cover
            pass


def main() -> int:
    if not backend.anomaly_detection_enabled():
        logger.error("anomaly detection desabilitado por env; encerrando")
        return 1
    if not backend.detection_worker_enabled():
        logger.error("GMJFLOW_DETECTION_WORKER_ENABLED nao esta true; este entrypoint e o worker do detector")
        return 1

    _install_signal_handlers()
    backend.ensure_sensor_db()
    server = _start_http_server()

    ttl = backend.detection_lease_ttl_seconds()
    logger.info(
        "worker detector iniciado owner=%s lease_ttl=%ss interval=%ss reconcile=%s",
        OWNER,
        ttl,
        backend.detection_scheduler_interval_seconds(),
        backend.detection_reconcile_enabled(),
    )
    threading.Thread(target=_heartbeat_loop, name="gmj-flow-detector-heartbeat", daemon=True).start()

    interval = backend.detection_scheduler_interval_seconds()
    while not STOP.wait(interval):
        if not STATE["holding_lease"]:
            if backend.detection_lease_acquire(OWNER, ttl):
                STATE["holding_lease"] = True
                logger.info("lease do detector adquirido por %s", OWNER)
            else:
                lease = backend.detection_lease_info() or {}
                logger.warning("lease do detector detido por %s; aguardando", lease.get("owner"))
                continue
        started = time.monotonic()
        STATE["last_cycle_started_at"] = backend.utc_now_iso()
        try:
            result = backend.detect_anomalies_once()
            STATE["last_error"] = ""
            STATE["status"] = {
                "templates": (result or {}).get("template_detection", {}).get("scan_cache"),
                "rules_evaluated": (result or {}).get("template_detection", {}).get("rules_evaluated"),
            }
        except Exception as exc:  # pragma: no cover - resiliencia do worker
            STATE["last_error"] = backend.clean_text(exc)
            logger.warning("falha no ciclo do detector isolado: %s", exc)
        finally:
            STATE["cycles"] = int(STATE["cycles"]) + 1
            STATE["last_cycle_finished_at"] = backend.utc_now_iso()
            STATE["last_cycle_duration_seconds"] = round(time.monotonic() - started, 2)
            backend.detection_lease_renew(OWNER, ttl)
            logger.info(
                "ciclo %s concluido em %ss erro=%s",
                STATE["cycles"],
                STATE["last_cycle_duration_seconds"],
                STATE["last_error"] or "-",
            )
        # Publica estado proprio junto ao status compartilhado (observabilidade do worker).
        shared = backend.load_persisted_detection_status() or {}
        shared["worker"] = {
            "owner": OWNER,
            "cycles": STATE["cycles"],
            "last_cycle_duration_seconds": STATE.get("last_cycle_duration_seconds"),
            "last_cycle_started_at": STATE["last_cycle_started_at"],
            "last_cycle_finished_at": STATE["last_cycle_finished_at"],
            "last_error": STATE["last_error"],
        }
        backend.persist_detection_status(shared)

    logger.info("worker detector encerrando")
    backend.detection_lease_release(OWNER)
    server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
