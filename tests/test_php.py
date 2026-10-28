import unittest
from unittest import mock

import scanner


def php_result(status_code=200, body=b"ok", headers=None, error=None):
    return scanner.PhpHTTPResult(
        status_code=status_code,
        body=body,
        headers=dict(headers or {}),
        error=error,
    )


MEMORY_ERROR = (
    b"Allowed memory size of 134217728 bytes exhausted "
    b"(tried to allocate 1 bytes) in Unknown on line 0"
)


class PhpVersionTests(unittest.TestCase):
    def test_version_boundaries(self):
        cases = (
            ("PHP/8.2.34", "VULNERABLE"),
            ("PHP/8.2.35", "FIXED"),
            ("PHP/8.3.35", "VULNERABLE"),
            ("PHP/8.3.36", "FIXED"),
            ("PHP/8.4.26", "VULNERABLE"),
            ("PHP/8.4.27", "FIXED"),
            ("PHP/8.5.11", "VULNERABLE"),
            ("PHP/8.5.12", "FIXED"),
            ("PHP/7.4.33", None),
            ("PHP/8.2", None),
            ("tanpa versi", None),
        )
        for powered_by, expected in cases:
            with self.subTest(powered_by=powered_by):
                self.assertEqual(
                    scanner.php_version_verdict(powered_by), expected
                )


class PhpDifferentialBodyTests(unittest.TestCase):
    def test_valid_control_body_matches_probe_size(self):
        probe = scanner.php_build_probe_body(1, 4000)
        body = scanner.php_build_valid_control_body(len(probe))
        self.assertEqual(len(body), len(probe))
        self.assertTrue(body.startswith(b"--x\r\n"))
        self.assertTrue(body.endswith(b"\r\n--x--\r\n"))
        self.assertIn(b'name="file"', body)


class PhpCrashSignalTests(unittest.TestCase):
    def test_in_band_memory_error(self):
        signal, reason = scanner.php_crash_signal(
            php_result(), php_result(500, MEMORY_ERROR), "fpm"
        )
        self.assertEqual(signal, "PHP-FPM")
        self.assertIn("memori habis", reason)

    def test_empty_500_with_valid_differential(self):
        signal, reason = scanner.php_crash_signal(
            php_result(body=b"ok"),
            php_result(500, b""),
            "mod_php",
            differential=php_result(200, b"ok"),
        )
        self.assertEqual(signal, "mod_php")
        self.assertIn("kontrol valid", reason)

    def test_empty_500_without_differential_is_not_crash_signal(self):
        signal, reason = scanner.php_crash_signal(
            php_result(body=b"ok"), php_result(500, b""), "mod_php"
        )
        self.assertIsNone(signal)
        self.assertIsNone(reason)

    def test_empty_500_with_failed_differential_is_not_crash_signal(self):
        signal, reason = scanner.php_crash_signal(
            php_result(body=b"ok"),
            php_result(500, b""),
            "mod_php",
            differential=php_result(500, b""),
        )
        self.assertIsNone(signal)
        self.assertIsNone(reason)

    def test_fpm_gateway_status_with_differential_is_crash_signal(self):
        for status in (502, 503, 504):
            with self.subTest(status=status):
                signal, _reason = scanner.php_crash_signal(
                    php_result(),
                    php_result(status, b""),
                    "fpm",
                    differential=php_result(200, b"ok"),
                )
                self.assertEqual(signal, "PHP-FPM")

    def test_fpm_gateway_status_without_differential_is_not_crash_signal(self):
        signal, reason = scanner.php_crash_signal(
            php_result(), php_result(502, b""), "fpm"
        )
        self.assertIsNone(signal)
        self.assertIsNone(reason)

    def test_mod_php_gateway_status_is_not_crash_signal(self):
        signal, reason = scanner.php_crash_signal(
            php_result(),
            php_result(502, b""),
            "mod_php",
            differential=php_result(200, b"ok"),
        )
        self.assertIsNone(signal)
        self.assertIsNone(reason)

    def test_connection_reset_with_differential_is_crash_signal(self):
        signal, reason = scanner.php_crash_signal(
            php_result(body=b"ok"),
            php_result(error="koneksi tertutup sebelum respons selesai"),
            "fpm",
            differential=php_result(200, b"ok"),
        )
        self.assertEqual(signal, "PHP-FPM")
        self.assertIn("koneksi terputus", reason)

    def test_connection_reset_without_differential_is_not_crash_signal(self):
        signal, reason = scanner.php_crash_signal(
            php_result(body=b"ok"),
            php_result(error="connection reset by peer"),
            "fpm",
        )
        self.assertIsNone(signal)
        self.assertIsNone(reason)

    def test_timeout_is_not_crash_signal(self):
        signal, reason = scanner.php_crash_signal(
            php_result(body=b"ok"),
            php_result(error="permintaan timeout"),
            "fpm",
            differential=php_result(200, b"ok"),
        )
        self.assertIsNone(signal)
        self.assertIsNone(reason)

    def test_empty_200_with_valid_differential_is_crash_signal(self):
        signal, reason = scanner.php_crash_signal(
            php_result(body=b"ok"),
            php_result(200, b""),
            "fpm",
            differential=php_result(200, b"ok"),
        )
        self.assertEqual(signal, "PHP-FPM")
        self.assertIn("body kosong", reason)

    def test_empty_200_with_empty_differential_is_not_crash_signal(self):
        signal, reason = scanner.php_crash_signal(
            php_result(body=b"ok"),
            php_result(200, b""),
            "fpm",
            differential=php_result(200, b""),
        )
        self.assertIsNone(signal)
        self.assertIsNone(reason)

    def test_normal_response_is_not_crash_signal(self):
        signal, reason = scanner.php_crash_signal(
            php_result(), php_result(200, b"ok"), "fpm"
        )
        self.assertIsNone(signal)
        self.assertIsNone(reason)


class PhpCheckTests(unittest.TestCase):
    def run_check(self, responses, sapi="fpm"):
        with (
            mock.patch.object(scanner, "PHP_PROBES", ((1, 1),)),
            mock.patch.object(
                scanner, "php_build_probe_body", return_value=b"probe"
            ),
            mock.patch.object(
                scanner,
                "php_build_valid_control_body",
                return_value=b"valid-control",
            ),
            mock.patch.object(
                scanner, "php_send_post", side_effect=responses
            ) as send,
        ):
            result = scanner.php_check_url(
                "https://target.test",
                "https://target.test/index.php",
                5,
                True,
                {},
                sapi,
            )
        return result, send

    def test_control_error_skips_probe(self):
        result, send = self.run_check(
            [php_result(error="kesalahan koneksi")]
        )
        send.assert_called_once()
        self.assertEqual(result["verdict"], "ERROR")
        self.assertIn("kontrol", result["reason"])

    def test_blocked_control_is_inconclusive(self):
        result, send = self.run_check([php_result(403, b"blocked")])
        send.assert_called_once()
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("HTTP 403", result["error"])

    def test_crash_probe_is_vulnerable(self):
        result, send = self.run_check(
            [php_result(body=b"ok"), php_result(500, MEMORY_ERROR)]
        )
        self.assertEqual(send.call_count, 2)
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertEqual(result["sapi"], "PHP-FPM")
        self.assertIn("memori habis", result["reason"])

    def test_rejected_probe_is_inconclusive(self):
        result, send = self.run_check(
            [php_result(body=b"ok"), php_result(403, b"blocked")]
        )
        self.assertEqual(send.call_count, 2)
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("HTTP 403", result["error"])

    def test_rejected_probe_wins_over_vulnerable_version(self):
        result, send = self.run_check(
            [
                php_result(body=b"ok"),
                php_result(
                    403,
                    b"blocked",
                    headers={"X-Powered-By": "PHP/8.3.35"},
                ),
            ]
        )
        self.assertEqual(send.call_count, 2)
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("HTTP 403", result["error"])

    def test_fixed_powered_by_skips_probe(self):
        result, send = self.run_check(
            [php_result(headers={"X-Powered-By": "PHP/8.2.35"})]
        )
        self.assertEqual(send.call_count, 1)
        self.assertFalse(result["vulnerable"])
        self.assertEqual(result["verdict"], "FIXED")
        self.assertIn("8.2.35", result["reason"])

    def test_fixed_version_on_probe_wins_over_empty_500(self):
        result, send = self.run_check(
            [
                php_result(body=b"ok"),
                php_result(
                    500,
                    b"",
                    headers={"X-Powered-By": "PHP/8.2.35"},
                ),
            ]
        )
        self.assertEqual(send.call_count, 2)
        self.assertFalse(result["vulnerable"])
        self.assertEqual(result["verdict"], "FIXED")
        self.assertIn("8.2.35", result["reason"])

    def test_empty_500_with_valid_differential_is_vulnerable(self):
        result, send = self.run_check(
            [
                php_result(body=b"ok"),
                php_result(500, b""),
                php_result(200, b"valid"),
            ]
        )
        self.assertEqual(send.call_count, 3)
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertEqual(result["sapi"], "PHP-FPM")
        self.assertEqual(result["differential"]["status_code"], 200)
        self.assertIn("kontrol valid", result["reason"])

    def test_empty_500_with_failed_differential_is_inconclusive(self):
        result, send = self.run_check(
            [
                php_result(body=b"ok"),
                php_result(500, b""),
                php_result(500, b""),
            ]
        )
        self.assertEqual(send.call_count, 3)
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("kontrol valid multipart membalas HTTP 500", result["error"])
        self.assertIn("suspicion", result)
        self.assertIsNotNone(result["suspicion"])

    def test_empty_500_with_vulnerable_version_is_vulnerable(self):
        result, send = self.run_check(
            [
                php_result(
                    body=b"ok",
                    headers={"X-Powered-By": "PHP/8.3.35"},
                ),
                php_result(500, b""),
                php_result(500, b""),
            ]
        )
        self.assertEqual(send.call_count, 3)
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertIn("8.3.35", result["reason"])

    def test_connection_reset_with_valid_differential_is_vulnerable(self):
        result, send = self.run_check(
            [
                php_result(body=b"ok"),
                php_result(error="koneksi tertutup sebelum respons selesai"),
                php_result(200, b"valid"),
            ]
        )
        self.assertEqual(send.call_count, 3)
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertIn("koneksi terputus", result["reason"])

    def test_connection_reset_with_failed_differential_is_inconclusive(self):
        result, send = self.run_check(
            [
                php_result(body=b"ok"),
                php_result(error="connection reset by peer"),
                php_result(500, b""),
            ]
        )
        self.assertEqual(send.call_count, 3)
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("kontrol valid multipart", result["error"])

    def test_timeout_does_not_send_differential(self):
        result, send = self.run_check(
            [
                php_result(body=b"ok"),
                php_result(error="permintaan timeout"),
            ]
        )
        self.assertEqual(send.call_count, 2)
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("timeout", result["error"])

    def test_empty_200_with_valid_differential_is_vulnerable(self):
        result, send = self.run_check(
            [
                php_result(body=b"ok"),
                php_result(200, b""),
                php_result(200, b"valid"),
            ]
        )
        self.assertEqual(send.call_count, 3)
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["verdict"], "VULNERABLE")

    def test_empty_200_with_empty_differential_is_inconclusive(self):
        result, send = self.run_check(
            [
                php_result(body=b"ok"),
                php_result(200, b""),
                php_result(200, b""),
            ]
        )
        self.assertEqual(send.call_count, 3)
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_vulnerable_powered_by(self):
        result, send = self.run_check(
            [
                php_result(headers={"X-Powered-By": "PHP/8.3.35"}),
                php_result(body=b"ok"),
            ]
        )
        self.assertEqual(send.call_count, 2)
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertIn("8.3.35", result["reason"])

    def test_no_signal(self):
        result, send = self.run_check(
            [php_result(body=b"ok"), php_result(body=b"ok")]
        )
        self.assertEqual(send.call_count, 2)
        self.assertFalse(result["vulnerable"])
        self.assertEqual(result["verdict"], "NO SIGNAL")

    def test_probe_error_is_inconclusive(self):
        result, send = self.run_check(
            [
                php_result(body=b"ok"),
                php_result(error="permintaan timeout"),
            ]
        )
        self.assertEqual(send.call_count, 2)
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("timeout", result["error"])


if __name__ == "__main__":
    unittest.main()
