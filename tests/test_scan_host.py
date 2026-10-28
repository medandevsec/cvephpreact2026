import unittest
from unittest import mock

import scanner


def fingerprint(status_code=200, tech=None, details=None, blocked=False):
    tech = list(tech or ["Next.js", "React", "Node.js"])
    details = list(
        details
        or [
            {"name": "Next.js", "confidence": "high"},
            {"name": "React", "confidence": "high"},
            {"name": "Node.js", "confidence": "medium"},
        ]
    )
    return {
        "baseline_url": "https://target.test/",
        "status_code": status_code,
        "server": None,
        "powered_by": None,
        "tech": tech,
        "tech_details": details,
        "tech_summary": "PHP=tidak terlihat",
        "router_version": None,
        "waf": [],
        "challenge": False,
        "blocked": blocked,
        "headers": {},
        "reason": None,
        "error": None,
        "timestamp": "2026-10-26T00:00:00Z",
    }


def php_finding(status_code=500):
    return {
        "engine": "php",
        "cve": scanner.PHP_CVES,
        "host": "https://target.test",
        "vulnerable": None,
        "verdict": "INCONCLUSIVE",
        "status_code": status_code,
        "error": "probe inconclusive",
        "reason": "probe inconclusive",
        "skipped": False,
        "skip_reason": None,
    }


def simple_finding(engine, vulnerable):
    return {
        "engine": engine,
        "cve": "test",
        "host": "https://target.test",
        "vulnerable": vulnerable,
        "verdict": "NOT VULNERABLE"
        if vulnerable is False
        else "INCONCLUSIVE",
        "status_code": 200,
        "error": None,
        "reason": None,
    }


class ScanHostStatusTests(unittest.TestCase):
    def test_host_status_uses_baseline_not_probe(self):
        with (
            mock.patch.object(
                scanner, "collect_fingerprint", return_value=fingerprint()
            ),
            mock.patch.object(
                scanner, "php_check_vulnerability", return_value=php_finding()
            ),
        ):
            result = scanner.scan_host(
                host="https://target.test",
                mode="php",
                timeout=5,
                verify_ssl=True,
                custom_headers={},
                sapi="auto",
                paths=None,
                safe_check=True,
                windows=False,
                waf_bypass=False,
                waf_bypass_size_kb=128,
                vercel_waf_bypass=False,
            )
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_host_status_falls_back_to_finding_without_baseline(self):
        with mock.patch.object(
            scanner, "php_check_vulnerability", return_value=php_finding()
        ):
            result = scanner.scan_host(
                host="https://target.test",
                mode="php",
                timeout=5,
                verify_ssl=True,
                custom_headers={},
                sapi="auto",
                paths=None,
                safe_check=True,
                windows=False,
                waf_bypass=False,
                waf_bypass_size_kb=128,
                vercel_waf_bypass=False,
                baseline=False,
            )
        self.assertEqual(result["status_code"], 500)


class PhpGateTests(unittest.TestCase):
    def test_gate_only_applies_to_all_mode(self):
        fp = fingerprint()
        self.assertIsNotNone(scanner.php_skip_reason("all", None, fp))
        self.assertIsNone(scanner.php_skip_reason("php", None, fp))

    def test_gate_keeps_explicit_php_path(self):
        fp = fingerprint()
        self.assertIsNone(
            scanner.php_skip_reason("all", ["/index.php"], fp)
        )

    def test_gate_keeps_explicit_php_target_url(self):
        fp = fingerprint()
        fp["baseline_url"] = "https://target.test/index.php"
        self.assertIsNone(scanner.php_skip_reason("all", None, fp))

    def test_gate_keeps_target_with_php_indicator(self):
        fp = fingerprint(
            tech=["Next.js", "PHP/8.3.35"],
            details=[
                {"name": "Next.js", "confidence": "high"},
                {"name": "PHP", "confidence": "high"},
            ],
        )
        self.assertIsNone(scanner.php_skip_reason("all", None, fp))

    def test_gate_skips_php_in_all_mode(self):
        with (
            mock.patch.object(
                scanner, "collect_fingerprint", return_value=fingerprint()
            ),
            mock.patch.object(scanner, "php_check_vulnerability") as php,
            mock.patch.object(
                scanner,
                "react_check_vulnerability",
                return_value=simple_finding("react", False),
            ),
            mock.patch.object(
                scanner,
                "react_router_check_vulnerability",
                return_value=simple_finding("react-router", False),
            ),
            mock.patch.object(
                scanner,
                "nodejs_check_vulnerability",
                return_value=simple_finding("nodejs", None),
            ),
            mock.patch.object(
                scanner,
                "nginx_check_vulnerability",
                return_value=simple_finding("nginx", False),
            ),
        ):
            result = scanner.scan_host(
                host="https://target.test",
                mode="all",
                timeout=5,
                verify_ssl=True,
                custom_headers={},
                sapi="auto",
                paths=None,
                safe_check=True,
                windows=False,
                waf_bypass=False,
                waf_bypass_size_kb=128,
                vercel_waf_bypass=False,
            )
        php.assert_not_called()
        self.assertEqual(result["findings"][0]["engine"], "php")
        self.assertTrue(result["findings"][0]["skipped"])
        self.assertFalse(result["findings"][0]["vulnerable"])
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["verdict"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
