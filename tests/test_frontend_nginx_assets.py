from __future__ import annotations

import os
import re
import subprocess
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
NGINX = (ROOT / "frontend" / "nginx.conf").read_text(encoding="utf-8")


def local_script_sources() -> list[str]:
    sources = re.findall(
        r'<script\b[^>]*\bsrc=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
        INDEX,
        flags=re.IGNORECASE,
    )
    return sorted({
        source.split("?", 1)[0]
        for source in sources
        if not re.match(r"^(?:https?:)?//", source)
    })


def compose_javascript_mounts() -> dict[str, str]:
    mounts = {}
    for source, target in re.findall(
        r"^\s*-\s+\./frontend/([^:\s]+\.js)"
        r":/usr/share/nginx/html/([^:\s]+\.js):ro\s*$",
        COMPOSE,
        flags=re.MULTILINE,
    ):
        mounts[target] = source
    return mounts


class FrontendNginxAssetContractTest(unittest.TestCase):
    def test_every_local_script_exists_and_has_an_explicit_read_only_mount(self):
        scripts = local_script_sources()
        mounts = compose_javascript_mounts()
        self.assertTrue(scripts)
        self.assertEqual(set(scripts), set(mounts))
        for script in scripts:
            self.assertEqual(mounts[script], script)
            self.assertTrue((ROOT / "frontend" / script).is_file(), script)

    def test_no_unreferenced_javascript_is_published(self):
        self.assertEqual(
            set(compose_javascript_mounts()),
            set(local_script_sources()),
        )

    def test_missing_javascript_is_404_not_spa_fallback(self):
        self.assertRegex(NGINX, r"location\s+~\*\s+\\\.js\$")
        self.assertIn("try_files $uri =404;", NGINX)
        self.assertIn('X-Content-Type-Options "nosniff"', NGINX)

    def test_cors_is_closed_when_environment_variable_is_absent(self):
        self.assertIn('API_CORS_ORIGINS: "${API_CORS_ORIGINS-}"', COMPOSE)
        self.assertNotIn('API_CORS_ORIGINS: "${API_CORS_ORIGINS-*}"', COMPOSE)

    def test_required_runtime_files_are_present_and_not_ignored(self):
        required = (
            "backend/app/services/time_buckets.py",
            "frontend/dashboard-time-range.js",
            "scripts/check_pmacct_collectors.sh",
            "scripts/install-exabgp.sh",
            "scripts/install-systemd-service.sh",
            "scripts/post-install-check.sh",
            "deploy/exabgp/gmj-flow-exabgp.conf.template",
            "deploy/systemd/gmj-flow.service.template",
            "tests/test_time_buckets.py",
            "tests/test_grafana_integration_static.py",
            "tests/test_frontend_nginx_assets.py",
        )
        for relative in required:
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
            ignored = subprocess.run(
                ["git", "check-ignore", "--quiet", "--", relative],
                cwd=ROOT,
                check=False,
            )
            self.assertNotEqual(ignored.returncode, 0, relative)
        self.assertIn("from app.services.time_buckets import", (
            ROOT / "backend" / "app" / "main.py"
        ).read_text(encoding="utf-8"))
        self.assertIn(
            '<script src="dashboard-time-range.js"></script>',
            INDEX,
        )


@unittest.skipUnless(
    os.getenv("GMJFLOW_RUN_DOCKER_TESTS") == "1",
    "set GMJFLOW_RUN_DOCKER_TESTS=1 for the temporary nginx container",
)
class FrontendNginxHttpTest(unittest.TestCase):
    def test_real_nginx_serves_javascript_and_rejects_missing_asset(self):
        docker_check = subprocess.run(
            ["docker", "info"],
            check=False,
            capture_output=True,
            text=True,
        )
        if docker_check.returncode != 0:
            self.skipTest("Docker daemon is unavailable")

        container_name = f"gmj-flow-nginx-test-{uuid.uuid4().hex[:12]}"
        command = [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--name",
            container_name,
            "--publish",
            "127.0.0.1::80",
        ]
        mounts = {
            "/usr/share/nginx/html/index.html": ROOT / "frontend" / "index.html",
            "/etc/nginx/conf.d/default.conf": ROOT / "frontend" / "nginx.conf",
        }
        mounts.update({
            f"/usr/share/nginx/html/{script}": ROOT / "frontend" / script
            for script in local_script_sources()
        })
        for target, source in mounts.items():
            command.extend([
                "--mount",
                f"type=bind,source={source.resolve()},target={target},readonly",
            ])
        command.append("nginx:1.27-alpine")

        try:
            started = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(started.returncode, 0, started.stderr)
            published = subprocess.run(
                ["docker", "port", container_name, "80/tcp"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            port = int(published.rsplit(":", 1)[1])
            base_url = f"http://127.0.0.1:{port}"

            last_error = None
            for _attempt in range(30):
                try:
                    with urllib.request.urlopen(
                        f"{base_url}/index.html",
                        timeout=1,
                    ) as response:
                        if response.status == 200:
                            break
                except Exception as exc:  # pragma: no cover - startup polling
                    last_error = exc
                    time.sleep(0.2)
            else:
                self.fail(f"temporary nginx did not start: {last_error}")

            for script in local_script_sources():
                with urllib.request.urlopen(
                    f"{base_url}/{script}",
                    timeout=3,
                ) as response:
                    body = response.read().decode("utf-8", errors="replace")
                    content_type = response.headers.get_content_type()
                self.assertEqual(response.status, 200, script)
                self.assertRegex(content_type, r"(?:java|ecma)script")
                self.assertNotIn("<!doctype html>", body.lower(), script)

            with self.assertRaises(urllib.error.HTTPError) as missing:
                urllib.request.urlopen(
                    f"{base_url}/missing-dashboard-module.js",
                    timeout=3,
                )
            self.assertEqual(missing.exception.code, 404)
            missing_body = missing.exception.read().decode(
                "utf-8",
                errors="replace",
            )
            self.assertNotIn("<!doctype html>", missing_body.lower())
        finally:
            subprocess.run(
                ["docker", "rm", "--force", container_name],
                check=False,
                capture_output=True,
                text=True,
            )


if __name__ == "__main__":
    unittest.main()
