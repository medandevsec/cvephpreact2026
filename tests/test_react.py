import unittest
from unittest import mock

import scanner


class FakeResponse:
    def __init__(
        self, status_code=200, text="", headers=None, reason="OK"
    ):
        self.status_code = status_code
        self.text = text
        self.headers = dict(headers or {})
        self.reason = reason


SAFE_MARKER = 'E{"digest":"abc"}'
RCE_REDIRECT = "/login?a=11111"


class ReactSafeCheckTests(unittest.TestCase):
    def test_500_with_digest_marker_is_vulnerable(self):
        response = FakeResponse(500, SAFE_MARKER)
        self.assertTrue(scanner.react_is_vulnerable_safe_check(response))

    def test_non_500_is_not_vulnerable(self):
        response = FakeResponse(200, SAFE_MARKER)
        self.assertFalse(scanner.react_is_vulnerable_safe_check(response))

    def test_500_without_digest_marker_is_not_vulnerable(self):
        response = FakeResponse(500, "internal server error")
        self.assertFalse(scanner.react_is_vulnerable_safe_check(response))

    def test_netlify_vary_mitigation(self):
        response = FakeResponse(
            500, SAFE_MARKER, headers={"Netlify-Vary": "query"}
        )
        self.assertFalse(scanner.react_is_vulnerable_safe_check(response))

    def test_netlify_and_vercel_server_mitigation(self):
        for server in ("netlify", "vercel", "Netlify", "Vercel"):
            with self.subTest(server=server):
                response = FakeResponse(
                    500, SAFE_MARKER, headers={"Server": server}
                )
                self.assertFalse(
                    scanner.react_is_vulnerable_safe_check(response)
                )


class ReactRceCheckTests(unittest.TestCase):
    def test_login_redirect_is_vulnerable(self):
        response = FakeResponse(
            200, headers={"X-Action-Redirect": RCE_REDIRECT}
        )
        self.assertTrue(scanner.react_is_vulnerable_rce_check(response))

    def test_prefixed_login_redirect_is_vulnerable(self):
        response = FakeResponse(
            200,
            headers={"X-Action-Redirect": "https://example.test/login?a=11111"},
        )
        self.assertTrue(scanner.react_is_vulnerable_rce_check(response))

    def test_unrelated_redirect_is_not_vulnerable(self):
        response = FakeResponse(
            200, headers={"X-Action-Redirect": "/dashboard"}
        )
        self.assertFalse(scanner.react_is_vulnerable_rce_check(response))


class ReactRouterVersionTests(unittest.TestCase):
    def test_php_powered_by_is_not_a_react_router_version(self):
        self.assertIsNone(
            scanner.react_router_extract_version(
                "", {"x-powered-by": "PHP/8.3.32"}
            )
        )

    def test_explicit_react_router_header_is_a_version(self):
        self.assertEqual(
            scanner.react_router_extract_version(
                "", {"x-react-router-version": "7.13.1"}
            ),
            "7.13.1",
        )

    def test_react_router_powered_by_is_a_version(self):
        self.assertEqual(
            scanner.react_router_extract_version(
                "", {"x-powered-by": "React Router/7.13.1"}
            ),
            "7.13.1",
        )

    def test_php_powered_by_does_not_fingerprint_react_router(self):
        details = scanner.fingerprint_tech_details(
            {"x-powered-by": "PHP/8.3.32"}, b""
        )
        names = {detail["name"] for detail in details}
        self.assertIn("PHP", names)
        self.assertNotIn("React Router", names)


class ReactCheckTests(unittest.TestCase):
    def run_check(self, response, error=None, safe_check=True):
        with mock.patch.object(
            scanner,
            "react_send_payload",
            return_value=(response, error),
        ) as send:
            result = scanner.react_check_vulnerability(
                "https://target.test",
                paths=["/"],
                safe_check=safe_check,
                follow_redirects=False,
            )
        return result, send

    def test_safe_check_vulnerable(self):
        result, send = self.run_check(FakeResponse(500, SAFE_MARKER))
        send.assert_called_once()
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["verdict"], "VULNERABLE")

    def test_safe_check_mitigated_is_not_vulnerable(self):
        result, send = self.run_check(
            FakeResponse(500, SAFE_MARKER, headers={"Server": "Vercel"})
        )
        send.assert_called_once()
        self.assertFalse(result["vulnerable"])
        self.assertEqual(result["verdict"], "NOT VULNERABLE")

    def test_rce_redirect_vulnerable(self):
        result, send = self.run_check(
            FakeResponse(200, headers={"X-Action-Redirect": RCE_REDIRECT}),
            safe_check=False,
        )
        send.assert_called_once()
        self.assertTrue(result["vulnerable"])
        self.assertEqual(result["verdict"], "VULNERABLE")

    def test_blocked_status_is_inconclusive(self):
        result, send = self.run_check(FakeResponse(403, "blocked"))
        send.assert_called_once()
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertIn("HTTP 403", result["reason"])

    def test_normal_response_is_not_vulnerable(self):
        result, send = self.run_check(FakeResponse(200, "ok"))
        send.assert_called_once()
        self.assertFalse(result["vulnerable"])
        self.assertEqual(result["verdict"], "NOT VULNERABLE")

    def test_transport_error_is_error(self):
        result, send = self.run_check(None, error="permintaan timeout")
        send.assert_called_once()
        self.assertEqual(result["verdict"], "ERROR")
        self.assertIn("timeout", result["error"])


if __name__ == "__main__":
    unittest.main()
