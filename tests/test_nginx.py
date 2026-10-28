import unittest
from unittest import mock

import scanner


class FakeResponse:
    def __init__(self, status_code=200, headers=None, reason="OK"):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.reason = reason
        self.text = ""


def affected_nginx_passive(**overrides):
    result = scanner.nginx_base_result("https://target.test")
    result.update(
        {
            "host": "https://target.test",
            "nginx_detected": True,
            "version": "1.30.0",
            "version_affected": True,
            "status_code": 200,
            "verdict": "INCONCLUSIVE",
            "tested_path": "/api",
        }
    )
    result.update(overrides)
    return result


class NginxProbeTests(unittest.TestCase):
    def run_probe(self, control, probe, liveness):
        with mock.patch.object(
            scanner,
            "nginx_check_vulnerability",
            return_value=affected_nginx_passive(),
        ), mock.patch.object(
            scanner,
            "nginx_poc_send",
            side_effect=[control, probe],
        ) as send, mock.patch.object(
            scanner,
            "nginx_liveness_probe",
            side_effect=liveness,
        ) as liveness_probe, mock.patch.object(
            scanner.time, "sleep"
        ):
            result = scanner.nginx_poc_check_vulnerability(
                "https://target.test", paths=["/api"]
            )
        return result, send, liveness_probe

    def test_payload_and_negative_control_length(self):
        for prefix in ("/api", "/api/v1", "/", "login"):
            with self.subTest(prefix=prefix):
                normalized = "/" + prefix.strip("/")
                if normalized == "/":
                    normalized = ""
                path = scanner.nginx_poc_build_path(prefix)
                control = scanner.nginx_poc_build_control_path(prefix)
                self.assertEqual(
                    path,
                    normalized + "/" + "A" * 349 + "+" * 400 + "A" * 6,
                )
                self.assertEqual(
                    control, normalized + "/" + "A" * 755
                )
                self.assertEqual(len(control), len(path))
                self.assertNotIn("+", control)

        self.assertEqual(len(scanner.nginx_poc_build_path("/api")), 760)

    def test_crash_like_markers(self):
        for error in (
            "Connection reset by peer",
            "connection aborted",
            "remote end closed connection",
            "unexpected_eof while reading",
            "forcibly closed by the remote host",
            "WinError 10054",
        ):
            with self.subTest(error=error):
                self.assertTrue(scanner.nginx_poc_crash_like(error))

        for error in (
            None,
            "permintaan timeout",
            "koneksi ditolak: connection refused",
            "kesalahan SSL: certificate verify failed",
        ):
            with self.subTest(error=error):
                self.assertFalse(scanner.nginx_poc_crash_like(error))

    def test_negative_control_reset_aborts_before_overflow_probe(self):
        result, send, liveness = self.run_probe(
            (None, b"", "koneksi terputus: Connection reset by peer"),
            (None, b"", "probe tidak boleh dikirim"),
            [],
        )

        send.assert_called_once()
        liveness.assert_not_called()
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertTrue(result["control_crash_like"])
        self.assertFalse(result["control_passed"])
        self.assertIn("Kontrol negatif", result["reason"])

    def test_negative_control_timeout_aborts_before_overflow_probe(self):
        result, send, liveness = self.run_probe(
            (None, b"", "permintaan timeout"),
            (None, b"", "probe tidak boleh dikirim"),
            [],
        )

        send.assert_called_once()
        liveness.assert_not_called()
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertFalse(result["control_crash_like"])
        self.assertFalse(result["control_passed"])

    def test_negative_control_without_response_aborts(self):
        result, send, liveness = self.run_probe(
            (None, b"", None),
            (None, b"", "probe tidak boleh dikirim"),
            [],
        )

        send.assert_called_once()
        liveness.assert_not_called()
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertFalse(result["control_passed"])
        self.assertIn("tidak menghasilkan respons", result["reason"])

    def test_negative_control_blocked_or_server_error_aborts(self):
        for status in (400, 403, 413, 414, 429, 500, 503):
            with self.subTest(status=status):
                result, send, liveness = self.run_probe(
                    (FakeResponse(status), b"blocked", None),
                    (None, b"", "probe tidak boleh dikirim"),
                    [],
                )

                send.assert_called_once()
                liveness.assert_not_called()
                self.assertIsNone(result["vulnerable"])
                self.assertEqual(result["verdict"], "INCONCLUSIVE")
                self.assertFalse(result["control_passed"])
                self.assertIn("Kontrol negatif", result["reason"])

    def test_negative_control_404_still_allows_probe(self):
        result, send, _liveness = self.run_probe(
            (FakeResponse(404), b"not found", None),
            (None, b"", "Connection reset by peer"),
            [(True, None)],
        )

        self.assertEqual(send.call_count, 2)
        self.assertTrue(result["control_passed"])
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["verdict"], "RENTAN")

    def test_probe_reset_with_recovery_is_vulnerable(self):
        result, send, liveness = self.run_probe(
            (FakeResponse(200), b"ok", None),
            (None, b"", "koneksi terputus: Connection reset by peer"),
            [(True, None)],
        )

        self.assertEqual(send.call_count, 2)
        liveness.assert_called_once()
        self.assertTrue(result["control_passed"])
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["verdict"], "RENTAN")
        self.assertTrue(result["liveness_recovered"])
        self.assertEqual(result["control_status_code"], 200)
        self.assertEqual(result["tested_path"], "/api")
        self.assertIn("Connection reset", result["probe_error"])

    def test_probe_reset_without_recovery_is_inconclusive(self):
        result, _send, liveness = self.run_probe(
            (FakeResponse(200), b"ok", None),
            (None, b"", "Connection reset by peer"),
            [(False, "server masih down")] * 3,
        )

        self.assertEqual(liveness.call_count, 3)
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertFalse(result.get("liveness_recovered", False))
        self.assertEqual(result["liveness_error"], "server masih down")

    def test_normal_probe_response_is_inconclusive(self):
        result, _send, liveness = self.run_probe(
            (FakeResponse(200), b"ok", None),
            (FakeResponse(200), b"ok", None),
            [(True, None)],
        )

        liveness.assert_called_once()
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("tidak terbukti", result["reason"])

    def test_probe_timeout_is_not_treated_as_crash(self):
        result, _send, _liveness = self.run_probe(
            (FakeResponse(200), b"ok", None),
            (None, b"", "permintaan timeout"),
            [(True, None)],
        )

        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("timeout", result["reason"])

    def test_baseline_blocked_skips_probe(self):
        with mock.patch.object(
            scanner,
            "nginx_check_vulnerability",
            return_value=affected_nginx_passive(),
        ), mock.patch.object(scanner, "nginx_poc_send") as send:
            result = scanner.nginx_poc_check_vulnerability(
                "https://target.test",
                paths=["/api"],
                baseline_blocked=True,
            )

        send.assert_not_called()
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("baseline", result["reason"])

    def test_fixed_version_skips_probe(self):
        with mock.patch.object(
            scanner,
            "nginx_check_vulnerability",
            return_value=affected_nginx_passive(
                version="1.30.1", version_affected=False
            ),
        ), mock.patch.object(scanner, "nginx_poc_send") as send:
            result = scanner.nginx_poc_check_vulnerability(
                "https://target.test", paths=["/api"]
            )

        send.assert_not_called()
        self.assertFalse(result["version_affected"])


if __name__ == "__main__":
    unittest.main()
