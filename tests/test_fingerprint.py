import unittest
from unittest import mock

import scanner


class FakeResponse:
    def __init__(self, status_code=200, body=b"", headers=None):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.body = body

    def iter_content(self, chunk_size):
        yield self.body

    def close(self):
        pass


class TechnologyDetailTests(unittest.TestCase):
    def test_nextjs_implies_react_and_node(self):
        details = scanner.fingerprint_tech_details(
            {"x-nextjs-cache": "HIT"},
            b"<script>self.__next_f.push(1)</script>",
        )
        names = {detail["name"] for detail in details}
        self.assertIn("Next.js", names)
        self.assertIn("React", names)
        self.assertIn("Node.js", names)
        node = next(detail for detail in details if detail["name"] == "Node.js")
        self.assertEqual(node["confidence"], "medium")

    def test_powered_by_nextjs_is_detected(self):
        details = scanner.fingerprint_tech_details(
            {"x-powered-by": "Next.js"}, b""
        )
        names = {detail["name"] for detail in details}
        self.assertIn("Next.js", names)
        self.assertIn("React", names)
        self.assertIn("Node.js", names)

    def test_php_version_and_cookie_are_detected(self):
        details = scanner.fingerprint_tech_details(
            {
                "x-powered-by": "PHP/8.3.35",
                "set-cookie": "PHPSESSID=abc",
            },
            b"",
        )
        php = next(detail for detail in details if detail["name"] == "PHP")
        self.assertEqual(php["confidence"], "high")
        self.assertEqual(php["version"], "8.3.35")
        self.assertIn("Set-Cookie: PHPSESSID", php["evidence"])

    def test_codeigniter_session_cookie_implies_php(self):
        details = scanner.fingerprint_tech_details(
            {"set-cookie": "ci_session=abc; Path=/; HttpOnly"}, b""
        )
        by_name = {detail["name"]: detail for detail in details}
        self.assertEqual(by_name["CodeIgniter"]["confidence"], "high")
        self.assertEqual(by_name["PHP"]["confidence"], "high")
        self.assertIn("Set-Cookie: ci_session", by_name["CodeIgniter"]["evidence"])
        summary = scanner.fingerprint_tech_summary(details)
        self.assertIn("PHP=terdeteksi", summary)
        self.assertIn("CodeIgniter=terdeteksi", summary)

    def test_codeigniter_csrf_cookie_is_detected(self):
        details = scanner.fingerprint_tech_details(
            {"set-cookie": "csrf_cookie_name=abc; Path=/"}, b""
        )
        by_name = {detail["name"]: detail for detail in details}
        self.assertEqual(by_name["CodeIgniter"]["confidence"], "medium")
        self.assertEqual(by_name["PHP"]["confidence"], "medium")
        summary = scanner.fingerprint_tech_summary(details)
        self.assertIn("PHP=terindikasi", summary)
        self.assertIn("CodeIgniter=terindikasi", summary)

    def test_codeigniter_body_marker_is_detected(self):
        details = scanner.fingerprint_tech_details(
            {}, b'<meta name="generator" content="CodeIgniter">'
        )
        by_name = {detail["name"]: detail for detail in details}
        self.assertEqual(by_name["CodeIgniter"]["confidence"], "low")
        self.assertEqual(by_name["PHP"]["confidence"], "low")
        summary = scanner.fingerprint_tech_summary(details)
        self.assertIn("PHP=indikasi lemah", summary)
        self.assertIn("CodeIgniter=indikasi lemah", summary)

    def test_codeigniter_csrf_form_field_is_detected(self):
        details = scanner.fingerprint_tech_details(
            {},
            b'<input type="hidden" name="csrf_test_name" value="abc">',
        )
        by_name = {detail["name"]: detail for detail in details}
        self.assertEqual(by_name["CodeIgniter"]["confidence"], "medium")
        self.assertIn(
            "body memuat csrf_test_name",
            by_name["CodeIgniter"]["evidence"],
        )

    def test_codeigniter_index_php_link_is_detected(self):
        details = scanner.fingerprint_tech_details(
            {}, b'<a href="/index.php/login">Masuk</a>'
        )
        by_name = {detail["name"]: detail for detail in details}
        self.assertEqual(by_name["CodeIgniter"]["confidence"], "low")
        self.assertIn("body: /index.php/", by_name["CodeIgniter"]["evidence"])

    def test_codeigniter_name_in_cookie_value_is_ignored(self):
        details = scanner.fingerprint_tech_details(
            {"set-cookie": "widget=ci_session; Path=/"}, b""
        )
        names = {detail["name"] for detail in details}
        self.assertNotIn("CodeIgniter", names)
        self.assertNotIn("PHP", names)

    def test_wordpress_is_detected_as_cms_and_php(self):
        details = scanner.fingerprint_tech_details(
            {},
            b'<link rel="stylesheet" href="/wp-content/themes/x/style.css">',
        )
        by_name = {detail["name"]: detail for detail in details}
        self.assertEqual(by_name["WordPress"]["confidence"], "high")
        self.assertEqual(by_name["PHP"]["confidence"], "high")
        summary = scanner.fingerprint_tech_summary(details)
        self.assertIn("WordPress=terdeteksi", summary)
        self.assertIn("PHP=terdeteksi", summary)

    def test_drupal_and_joomla_are_detected(self):
        drupal = scanner.fingerprint_tech_details(
            {"x-drupal-cache": "HIT"}, b""
        )
        joomla = scanner.fingerprint_tech_details(
            {}, b'<script src="/media/system/js/core.js"></script>'
        )
        self.assertIn("Drupal", {detail["name"] for detail in drupal})
        self.assertIn("Joomla", {detail["name"] for detail in joomla})

    def test_local_cms_are_detected(self):
        cases = (
            ("Lokomedia", b'<a href="media.php?module=home">Home</a>'),
            ("PopojiCMS", b'<link href="/po-content/themes/x/style.css">'),
            ("OpenSID", b'<meta name="generator" content="OpenSID">'),
            ("CiFireCMS", b"<title>CiFireCMS</title>"),
            ("Swarakalibata", b"<title>Swarakalibata</title>"),
        )
        for name, marker in cases:
            with self.subTest(cms=name):
                details = scanner.fingerprint_tech_details({}, marker)
                names = {detail["name"] for detail in details}
                self.assertIn(name, names)
                self.assertIn("PHP", names)

    def test_plain_page_does_not_claim_a_cms(self):
        details = scanner.fingerprint_tech_details(
            {}, b"<html><body>Tutorial WordPress dan Joomla</body></html>"
        )
        names = {detail["name"] for detail in details}
        self.assertNotIn("WordPress", names)
        self.assertNotIn("Joomla", names)
        self.assertNotIn("Drupal", names)

    def test_nginx_server_version_is_detected(self):
        details = scanner.fingerprint_tech_details(
            {"server": "nginx/1.30.0"}, b""
        )
        nginx = next(detail for detail in details if detail["name"] == "NGINX")
        self.assertEqual(nginx["version"], "1.30.0")
        self.assertIn("Server: nginx/1.30.0", nginx["evidence"])

    def test_express_is_detected_as_node(self):
        details = scanner.fingerprint_tech_details(
            {"x-powered-by": "Express"}, b""
        )
        node = next(detail for detail in details if detail["name"] == "Node.js")
        self.assertEqual(node["confidence"], "high")

    def test_summary_distinguishes_visible_and_invisible(self):
        details = scanner.fingerprint_tech_details(
            {"x-nextjs-cache": "HIT"}, b""
        )
        summary = scanner.fingerprint_tech_summary(details)
        self.assertIn("PHP=tidak terlihat", summary)
        self.assertIn("React=terdeteksi", summary)
        self.assertIn("Node.js=terindikasi", summary)
        self.assertIn("NGINX=tidak terlihat", summary)

    def test_blocked_summary_marks_incomplete(self):
        summary = scanner.fingerprint_tech_summary([], blocked=True)
        self.assertIn("baseline diblokir; hasil tidak lengkap", summary)


class CmsCatalogTests(unittest.TestCase):
    def test_catalog_names_are_unique(self):
        names = [signature["name"] for signature in scanner.CMS_SIGNATURES]
        self.assertEqual(len(names), len(set(names)))

    def test_catalog_signatures_are_valid(self):
        for signature in scanner.CMS_SIGNATURES:
            with self.subTest(cms=signature["name"]):
                self.assertTrue(
                    signature["cookies"]
                    or signature["headers"]
                    or signature["body"]
                )
                self.assertIsInstance(signature["php"], bool)
                for prefix, confidence in signature["cookies"]:
                    self.assertTrue(prefix)
                    self.assertIn(confidence, scanner.TECH_CONFIDENCE_RANK)
                for header_name, marker, confidence in signature["headers"]:
                    self.assertEqual(header_name, header_name.lower())
                    self.assertEqual(marker, marker.lower())
                    self.assertIn(confidence, scanner.TECH_CONFIDENCE_RANK)
                for marker, confidence in signature["body"]:
                    self.assertIsInstance(marker, bytes)
                    self.assertEqual(marker, marker.lower())
                    self.assertIn(confidence, scanner.TECH_CONFIDENCE_RANK)

    def test_header_presence_signature_matches_empty_value(self):
        details = scanner.fingerprint_tech_details({"x-drupal-cache": ""}, b"")
        self.assertIn("Drupal", {detail["name"] for detail in details})

    def test_every_cms_signature_is_reachable(self):
        for signature in scanner.CMS_SIGNATURES:
            with self.subTest(cms=signature["name"]):
                if signature["body"]:
                    details = scanner.fingerprint_tech_details(
                        {}, signature["body"][0][0]
                    )
                elif signature["cookies"]:
                    prefix = signature["cookies"][0][0]
                    details = scanner.fingerprint_tech_details(
                        {"set-cookie": f"{prefix}probe=1"}, b""
                    )
                else:
                    header_name, marker, _ = signature["headers"][0]
                    details = scanner.fingerprint_tech_details(
                        {header_name: marker or "probe"}, b""
                    )
                names = {detail["name"] for detail in details}
                self.assertIn(signature["name"], names)


class FingerprintIntegrationTests(unittest.TestCase):
    def collect(self, response):
        with (
            mock.patch.object(
                scanner.requests, "get", return_value=response
            ),
            mock.patch.object(scanner.RUNTIME, "wait"),
        ):
            return scanner.collect_fingerprint(
                "https://target.test", 5, True, {}
            )

    def test_nextjs_fingerprint_exposes_structured_details(self):
        result = self.collect(
            FakeResponse(
                headers={"x-nextjs-cache": "HIT"},
                body=b"<script>self.__next_f.push(1)</script>",
            )
        )
        self.assertEqual(result["status_code"], 200)
        self.assertIn("Next.js", result["tech"])
        self.assertIn("React", result["tech"])
        self.assertIn("Node.js", result["tech"])
        self.assertIn("React=terdeteksi", result["tech_summary"])
        self.assertIn("PHP=tidak terlihat", result["tech_summary"])

    def test_codeigniter_fingerprint_exposes_structured_details(self):
        result = self.collect(
            FakeResponse(
                headers={"set-cookie": "ci_session=abc; Path=/"},
                body=b"<html><body>Diskopukm</body></html>",
            )
        )
        self.assertIn("CodeIgniter", result["tech"])
        self.assertIn("PHP", result["tech"])
        self.assertIn("PHP=terdeteksi", result["tech_summary"])
        self.assertIn("CodeIgniter=terdeteksi", result["tech_summary"])

    def test_php_version_header_does_not_claim_react_router(self):
        result = self.collect(
            FakeResponse(
                headers={"x-powered-by": "PHP/8.3.32"},
                body=b"<html><body>WordPress</body></html>",
            )
        )
        self.assertIn("PHP", result["tech"])
        self.assertNotIn("React Router", result["tech"])
        self.assertIsNone(result["router_version"])
        self.assertNotIn("React Router", result["tech_summary"])

    def test_akamai_block_does_not_claim_absent_backend(self):
        result = self.collect(
            FakeResponse(
                status_code=403,
                headers={"content-type": "text/html"},
                body=(
                    b"<TITLE>Access Denied</TITLE>"
                    b"https://errors.edgesuite.net/18.abc"
                ),
            )
        )
        self.assertTrue(result["blocked"])
        self.assertIn("Akamai", result["waf"])
        self.assertEqual(result["tech_details"], [])
        self.assertIn(
            "baseline diblokir; hasil tidak lengkap", result["tech_summary"]
        )


if __name__ == "__main__":
    unittest.main()
