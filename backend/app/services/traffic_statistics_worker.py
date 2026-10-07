"""Optional standalone analytics scheduler. Never start the main/detector app.

GMJFLOW_STATISTICS_SCOPES='[{"type":"target","id":"192.0.2.1"}]'
python -m app.services.traffic_statistics_worker
"""

import json
import logging
import os
import signal
import threading
import time

from app.services.traffic_statistics import Scope, get_service


def run():
    logging.basicConfig(level=logging.INFO)
    scopes = [Scope(**s) for s in json.loads(os.environ["GMJFLOW_STATISTICS_SCOPES"])]
    if not 1 <= len(scopes) <= 8:
        raise ValueError("Configure between 1 and 8 analytics scopes")
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    service = get_service()
    while not stop.is_set():
        tick = int(time.time()) // 60 * 60
        for scope in scopes:
            if stop.is_set():
                break
            try:
                service.summary(scope, "5m", "PACKET_WEIGHTED", tick)
            except Exception:
                logging.exception("Analytics collection failed for %s", scope.key)
        stop.wait(max(1, 60 - time.time() % 60))


if __name__ == "__main__":
    run()
