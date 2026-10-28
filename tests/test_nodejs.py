import unittest
from unittest import mock

import brotli

import scanner


class FakeResponse:
    def __init__(
        self, status_code=200, content=b"", headers=None, reason="OK"
    ):
        self.status_code = status_code
        self.content = content
        self.headers = dict(headers or {})
        self.reason = reason


def passive_node(**overrides):
    result = {
        "engine": "nodejs",
        "cve": scanner.NODEJS_BROTLI_CVES,
        "host": "https://target.test",
        "vulnerable": None,
        "verdict": "INCONCLUSIVE",
        "status_code": 200,
        "error": None,
        "reason": (
            "Indikasi Node.js/Next.js terdeteksi (CVE-2026-111497). "
            "Versi Node.js tidak muncul di respons HTTP."
        ),
        "request": None,
        "response": None,
        "final_url": "https://target.test/",
        "tested_url": "https://target.test/",
        "timestamp": "2026-10-26T00:00:00Z",
    }
    result.update(overrides)
    return result


class NodeControlPayloadTests(unittest.TestCase):
    def test_control_payload_is_valid_brotli(self):
        self.assertEqual(
            brotli.decompress(scanner.NODEJS_BROTLI_CONTROL_PAYLOAD),
            b'{"ok":true}',
        )

    def test_control_check_passes_unblocked_response(self):
        result = scanner.nodejs_poc_control_check(
            FakeResponse(404, b"not found"), None
        )
        self.assertEqual(result, (False, "", None))

    def test_control_check_passes_400_without_decoder_marker(self):
        result = scanner.nodejs_poc_control_check(
            FakeResponse(400, b"invalid json"), None
        )
        self.assertEqual(result, (False, "", None))

    def test_control_check_rejects_blocked_status(self):
        blocked, reason, marker = scanner.nodejs_poc_control_check(
            FakeResponse(403, b"blocked"), None
        )
        self.assertTrue(blocked)
        self.assertIn("HTTP 403", reason)
        self.assertIsNone(marker)

    def test_control_check_rejects_decoder_marker(self):
        blocked, reason, marker = scanner.nodejs_poc_control_check(
            FakeResponse(200, b"ERROR_FORMAT_BLOCK_LENGTH_1"), None
        )
        self.assertTrue(blocked)
        self.assertIn("marker", reason)
        self.assertEqual(marker, "error_format_block_length_1")

    def test_control_check_rejects_transport_error(self):
        blocked, reason, marker = scanner.nodejs_poc_control_check(
            None, "permintaan timeout"
        )
        self.assertTrue(blocked)
        self.assertIn("timeout", reason)
        self.assertIsNone(marker)


class NodeClassifyTests(unittest.TestCase):
    def test_vulnerable_marker(self):
        vulnerable, _reason = scanner.nodejs_poc_classify(
            FakeResponse(500, b"ERROR_FORMAT_BLOCK_LENGTH_1"), None
        )
        self.assertTrue(vulnerable)

    def test_patched_marker(self):
        vulnerable, _reason = scanner.nodejs_poc_classify(
            FakeResponse(500, b"ERROR_FORMAT_BLOCK_SWITCH"), None
        )
        self.assertFalse(vulnerable)

    def test_generic_brotli_error_is_inconclusive(self):
        vulnerable, reason = scanner.nodejs_poc_classify(
            FakeResponse(400, b"brotli decompress failed"), None
        )
        self.assertIsNone(vulnerable)
        self.assertIn("Brotli decoding", reason)

    def test_plain_response_is_inconclusive(self):
        vulnerable, reason = scanner.nodejs_poc_classify(
            FakeResponse(200, b"ok"), None
        )
        self.assertIsNone(vulnerable)
        self.assertIn("tidak mendekode", reason)

    def test_timeout_is_inconclusive(self):
        vulnerable, reason = scanner.nodejs_poc_classify(
            None, "permintaan timeout"
        )
        self.assertIsNone(vulnerable)
        self.assertIn("timeout", reason)

    def test_missing_response_is_inconclusive(self):
        vulnerable, reason = scanner.nodejs_poc_classify(None, None)
        self.assertIsNone(vulnerable)
        self.assertIn("tidak ada respons", reason)


class NodePocTests(unittest.TestCase):
    def run_poc(self, responses, passive=None):
        side_effect = [
            item if isinstance(item, tuple) else (item, None)
            for item in responses
        ]
        with (
            mock.patch.object(
                scanner,
                "nodejs_check_vulnerability",
                return_value=passive or passive_node(),
            ),
            mock.patch.object(
                scanner, "nodejs_poc_send", side_effect=side_effect
            ) as send,
        ):
            result = scanner.nodejs_poc_check_vulnerability(
                "https://target.test", paths=["/"]
            )
        return result, send

    def test_valid_control_then_vulnerable_vector(self):
        result, send = self.run_poc(
            [
                FakeResponse(200, b"ok"),
                FakeResponse(500, b"ERROR_FORMAT_BLOCK_LENGTH_1"),
            ]
        )
        self.assertEqual(send.call_count, 2)
        self.assertTrue(result["control_passed"])
        self.assertEqual(result["control_status_code"], 200)
        self.assertIsNone(result["control_marker"])
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["verdict"], "RENTAN")
        self.assertEqual(result["status_code"], 500)

    def test_control_marker_aborts_before_poc(self):
        result, send = self.run_poc(
            [FakeResponse(200, b"ERROR_FORMAT_BLOCK_LENGTH_1")]
        )
        send.assert_called_once()
        self.assertFalse(result["control_passed"])
        self.assertEqual(result["control_marker"], "error_format_block_length_1")
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("Kontrol negatif", result["reason"])

    def test_patched_control_marker_aborts(self):
        result, send = self.run_poc(
            [FakeResponse(500, b"ERROR_FORMAT_BLOCK_SWITCH")]
        )
        send.assert_called_once()
        self.assertFalse(result["control_passed"])
        self.assertEqual(result["control_marker"], "error_format_block_switch")
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_control_500_aborts(self):
        result, send = self.run_poc([FakeResponse(500, b"server error")])
        send.assert_called_once()
        self.assertFalse(result["control_passed"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("HTTP 500", result["reason"])

    def test_control_400_without_marker_allows_poc(self):
        result, send = self.run_poc(
            [
                FakeResponse(400, b"invalid json"),
                FakeResponse(500, b"ERROR_FORMAT_BLOCK_LENGTH_1"),
            ]
        )
        self.assertEqual(send.call_count, 2)
        self.assertTrue(result["control_passed"])
        self.assertTrue(result["vulnerable"])

    def test_control_error_aborts(self):
        result, send = self.run_poc([(None, "permintaan timeout")])
        send.assert_called_once()
        self.assertFalse(result["control_passed"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("timeout", result["reason"])

    def test_control_without_response_aborts(self):
        result, send = self.run_poc([(None, None)])
        send.assert_called_once()
        self.assertFalse(result["control_passed"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("tidak ada respons", result["reason"])

    def test_all_vectors_patched(self):
        result, send = self.run_poc(
            [
                FakeResponse(200, b"ok"),
                FakeResponse(500, b"ERROR_FORMAT_BLOCK_SWITCH"),
                FakeResponse(500, b"ERROR_FORMAT_BLOCK_SWITCH"),
            ]
        )
        self.assertEqual(send.call_count, 3)
        self.assertTrue(result["control_passed"])
        self.assertFalse(result["vulnerable"])
        self.assertEqual(result["verdict"], "NOT VULNERABLE")

    def test_generic_vectors_are_inconclusive(self):
        result, send = self.run_poc(
            [
                FakeResponse(200, b"ok"),
                FakeResponse(200, b"ok"),
                FakeResponse(200, b"ok"),
            ]
        )
        self.assertEqual(send.call_count, 3)
        self.assertTrue(result["control_passed"])
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def test_timeout_vectors_are_inconclusive(self):
        result, send = self.run_poc(
            [
                FakeResponse(200, b"ok"),
                (None, "permintaan timeout"),
                (None, "permintaan timeout"),
            ]
        )
        self.assertEqual(send.call_count, 3)
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("timeout", result["reason"])

    def test_passive_blocked_skips_control(self):
        result, send = self.run_poc(
            [],
            passive=passive_node(
                status_code=403,
                reason="respons HTTP 403",
            ),
        )
        send.assert_not_called()
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("tidak dikirim", result["reason"])


if __name__ == "__main__":
    unittest.main()
