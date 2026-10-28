import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import scanner
import poc_chain
from e2e_support import FixtureTarget, Scenario


ROOT = Path(__file__).resolve().parents[1]


def scan(target: FixtureTarget, mode: str, **overrides) -> dict:
    options = {
        "mode": mode,
        "timeout": 5,
        "verify_ssl": True,
        "custom_headers": {},
        "sapi": "fpm",
        "paths": None,
        "safe_check": True,
        "windows": False,
        "waf_bypass": False,
        "waf_bypass_size_kb": 128,
        "vercel_waf_bypass": False,
        "nodejs_poc": False,
        "nginx_poc": False,
        "baseline": True,
    }
    options.update(overrides)
    return scanner.scan_host(target.url, **options)


class E2EBase(unittest.TestCase):
    def setUp(self):
        self.original_runtime = {
            "rate_limit": scanner.RUNTIME.rate_limit,
            "retries": scanner.RUNTIME.retries,
            "retry_backoff": scanner.RUNTIME.retry_backoff,
            "proxy": scanner.RUNTIME.proxy,
        }
        scanner.RUNTIME.rate_limit = 0
        scanner.RUNTIME.retries = 0
        scanner.RUNTIME.retry_backoff = 0
        scanner.RUNTIME.proxy = None

    def tearDown(self):
        for name, value in self.original_runtime.items():
            setattr(scanner.RUNTIME, name, value)


class PhpE2ETests(E2EBase):
    def test_crash_probe_and_valid_differential_are_vulnerable(self):
        with FixtureTarget(Scenario(php="crash")) as target:
            result = scan(target, "php")
            php_requests = target.state.matching("POST")

        self.assertEqual(result["verdict"], "VULNERABLE")
        finding = result["findings"][0]
        self.assertTrue(finding["vulnerable"])
        self.assertEqual(finding["sapi"], "PHP-FPM")
        self.assertIn("kontrol valid", finding["reason"])
        self.assertEqual(len(php_requests), 3)

    def test_patched_version_stops_before_probe(self):
        with FixtureTarget(Scenario(php="fixed")) as target:
            result = scan(target, "php")
            php_requests = target.state.matching("POST")

        self.assertEqual(result["verdict"], "NOT VULNERABLE")
        finding = result["findings"][0]
        self.assertEqual(finding["verdict"], "FIXED")
        self.assertEqual(len(php_requests), 1)


class ReactE2ETests(E2EBase):
    def test_safe_side_channel_vulnerable(self):
        with FixtureTarget(Scenario(react="safe-vulnerable")) as target:
            result = scan(target, "react")

        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertEqual(result["findings"][0]["verdict"], "VULNERABLE")

    def test_safe_side_channel_fixed(self):
        with FixtureTarget(Scenario(react="safe-fixed")) as target:
            result = scan(target, "react")

        self.assertEqual(result["verdict"], "NOT VULNERABLE")
        self.assertEqual(result["findings"][0]["verdict"], "NOT VULNERABLE")

    def test_rce_payload_detected_from_redirect_header(self):
        with FixtureTarget(Scenario(react="rce-vulnerable")) as target:
            result = scan(target, "react", safe_check=False)

        finding = result["findings"][0]
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertIn("X-Action-Redirect", finding["response"])


class ReactRouterE2ETests(E2EBase):
    def test_affected_version_is_inconclusive(self):
        with FixtureTarget(Scenario(react_router="affected")) as target:
            result = scan(target, "react-router")

        finding = result["findings"][0]
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertTrue(finding["framework"]["affected"])
        self.assertEqual(finding["framework"]["version"], "7.14.1")
        self.assertTrue(finding["framework"]["manifest_checked"])

    def test_fixed_version_is_not_vulnerable(self):
        with FixtureTarget(Scenario(react_router="fixed")) as target:
            result = scan(target, "react-router")

        finding = result["findings"][0]
        self.assertEqual(result["verdict"], "NOT VULNERABLE")
        self.assertFalse(finding["framework"]["affected"])
        self.assertEqual(finding["framework"]["version"], "7.14.2")

    def test_php_version_header_is_not_react_router(self):
        with FixtureTarget(Scenario(php="version")) as target:
            result = scan(target, "react-router")

        self.assertEqual(result["verdict"], "NOT VULNERABLE")
        self.assertIsNone(result["findings"][0]["framework"]["version"])


class NodeE2ETests(E2EBase):
    def test_passive_node_indicator_is_inconclusive(self):
        with FixtureTarget(Scenario(node_passive=True)) as target:
            result = scan(target, "nodejs")

        finding = result["findings"][0]
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertEqual(finding["engine"], "nodejs")

    def test_brotli_poc_vulnerable(self):
        with (
            FixtureTarget(
                Scenario(node_passive=True, node_poc="vulnerable")
            ) as target
        ):
            result = scan(target, "nodejs", nodejs_poc=True)

        finding = result["findings"][0]
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertTrue(finding["control_passed"])
        self.assertIn("FORMAT_BLOCK_LENGTH_1", finding["response"])

    def test_brotli_poc_patched(self):
        with (
            FixtureTarget(
                Scenario(node_passive=True, node_poc="patched")
            ) as target
        ):
            result = scan(target, "nodejs", nodejs_poc=True)

        finding = result["findings"][0]
        self.assertEqual(result["verdict"], "NOT VULNERABLE")
        self.assertIn("sudah dipatch", finding["reason"])


class NginxE2ETests(E2EBase):
    def test_affected_version_is_inconclusive(self):
        with FixtureTarget(Scenario(nginx="affected")) as target:
            result = scan(target, "nginx")

        finding = result["findings"][0]
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertTrue(finding["version_affected"])

    def test_fixed_version_is_not_vulnerable(self):
        with FixtureTarget(Scenario(nginx="fixed")) as target:
            result = scan(target, "nginx")

        self.assertEqual(result["verdict"], "NOT VULNERABLE")

    def test_poc_reset_with_liveness_recovery_is_vulnerable(self):
        with FixtureTarget(Scenario(nginx="poc-vulnerable")) as target:
            result = scan(target, "nginx", nginx_poc=True)
            paths = [item["path"] for item in target.state.matching("GET")]

        finding = result["findings"][0]
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertTrue(finding["control_passed"])
        self.assertTrue(finding["liveness_recovered"])
        self.assertTrue(any("+" in path for path in paths))

    def test_poc_without_crash_is_inconclusive(self):
        with FixtureTarget(Scenario(nginx="poc-patched")) as target:
            result = scan(target, "nginx", nginx_poc=True)

        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_blocked_control_never_sends_overflow_probe(self):
        with FixtureTarget(Scenario(nginx="poc-blocked")) as target:
            result = scan(target, "nginx", nginx_poc=True)
            paths = [item["path"] for item in target.state.matching("GET")]

        finding = result["findings"][0]
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertFalse(finding["control_passed"])
        self.assertTrue(any("A" * 700 in path for path in paths))
        self.assertFalse(any("+" in path for path in paths))


class ChainE2ETests(E2EBase):
    """Regresi rantai e2e RCE -> webshell via poc_chain.run_chain."""

    def test_chain_uploads_serves_executes_and_cleans_up(self):
        with FixtureTarget(Scenario(react="rce-upload")) as target:
            result = poc_chain.run_chain(target.url)
            gets = target.state.matching("GET")
            posts = target.state.matching("POST")
            shells = list(target.state.shells)

        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["engine"], "chain")
        self.assertEqual(
            finding["cve"], "CVE-2025-55182 / CVE-2025-66478"
        )
        self.assertTrue(finding["vulnerable"])

        stages = finding["stages"]
        self.assertEqual(
            [stage["name"] for stage in stages],
            ["upload", "serve", "exec", "cleanup"],
        )
        self.assertTrue(all(stage["ok"] for stage in stages))
        self.assertIn("<POC_OUT>", stages[2]["detail"])
        self.assertIsNotNone(
            scanner.CHAIN_SHELL_NAME_RE.fullmatch(finding["shell"])
        )

        # upload = POST bertoken POC_CHAIN_UPLOAD; exec = POST shell
        # dengan c=...; cleanup = POST bertoken POC_CHAIN_CLEANUP.
        self.assertEqual(len(posts), 3)
        self.assertIn(b"POC_CHAIN_UPLOAD", posts[0]["body"])
        exec_posts = [
            item
            for item in posts
            if scanner.CHAIN_SHELL_NAME_RE.fullmatch(
                item["path"].rsplit("/", 1)[-1]
            )
        ]
        self.assertEqual(len(exec_posts), 1)
        self.assertIn(b"POC_CHAIN_EXEC_OK", exec_posts[0]["body"])
        self.assertIn(b"POC_CHAIN_CLEANUP", posts[-1]["body"])

        # serve (GET shell) + verifikasi pasca-cleanup (GET shell lagi).
        shell_gets = [
            item
            for item in gets
            if scanner.CHAIN_SHELL_NAME_RE.fullmatch(
                item["path"].rsplit("/", 1)[-1]
            )
        ]
        self.assertEqual(len(shell_gets), 2)
        self.assertIn(f"/{finding['shell']}", shell_gets[0]["path"])
        self.assertEqual(shells, [])

    def test_chain_fixed_scenario_stops_at_upload(self):
        with FixtureTarget(Scenario(react="rce-fixed")) as target:
            result = poc_chain.run_chain(target.url)
            shells = list(target.state.shells)

        self.assertEqual(result["verdict"], "NOT VULNERABLE")
        finding = result["findings"][0]
        self.assertEqual(finding["engine"], "chain")
        self.assertFalse(finding["vulnerable"])
        self.assertTrue(
            all(not stage["ok"] for stage in finding["stages"])
        )
        self.assertIn("Rantai terputus", finding["reason"])
        self.assertEqual(shells, [])


class CliAllModeE2ETests(E2EBase):
    def test_cli_all_mode_writes_json_with_all_engines(self):
        scenario = Scenario(
            php="version",
            react="safe-vulnerable",
            react_router="affected",
            node_passive=True,
            node_poc="vulnerable",
            nginx="poc-vulnerable",
        )
        with FixtureTarget(scenario) as target:
            with tempfile.TemporaryDirectory() as temp_dir:
                output = Path(temp_dir) / "result.json"
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scanner.py"),
                        "-u",
                        target.url,
                        "--mode",
                        "all",
                        "--timeout",
                        "5",
                        "--retries",
                        "0",
                        "--nodejs-poc",
                        "--nginx-poc",
                        "--no-color",
                        "--all-results",
                        "-o",
                        str(output),
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    timeout=60,
                )
                self.assertEqual(
                    completed.returncode,
                    1,
                    completed.stdout + completed.stderr,
                )
                data = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(data["summary"]["total_scanned"], 1)
        self.assertEqual(data["summary"]["vulnerable"], 1)
        findings = data["results"][0]["findings"]
        engines = {item["engine"] for item in findings}
        self.assertEqual(
            engines,
            {"php", "react", "react-router", "nodejs", "nginx"},
        )
        self.assertEqual(
            {item["engine"]: item["cve"] for item in findings},
            {
                "php": "CVE-2026-109618 / CVE-2026-109619",
                "react": "CVE-2025-55182 / CVE-2025-66478",
                "react-router": "CVE-2026-42211",
                "nodejs": "CVE-2026-111497",
                "nginx": "CVE-2026-42945",
            },
        )
        verdicts = {
            item["engine"]: item["verdict"]
            for item in findings
        }
        self.assertEqual(verdicts["php"], "VULNERABLE")
        self.assertEqual(verdicts["react"], "VULNERABLE")
        self.assertEqual(verdicts["react-router"], "INCONCLUSIVE")
        self.assertEqual(verdicts["nodejs"], "RENTAN")
        self.assertEqual(verdicts["nginx"], "RENTAN")


if __name__ == "__main__":
    unittest.main()
