import os
import ssl
import tempfile
import unittest
from unittest import mock

import requests

import scanner


class TlsErrorMessageTests(unittest.TestCase):
    def test_certificate_verify_error_is_actionable(self):
        message = scanner.tls_error_message(
            RuntimeError(
                "certificate verify failed: unable to get local issuer "
                "certificate"
            )
        )
        self.assertIn("rantai sertifikat", message)
        self.assertIn("--ca-bundle", message)
        self.assertIn("--system-ca", message)
        self.assertIn("-k", message)

    def test_other_ssl_error_keeps_ssl_prefix(self):
        message = scanner.tls_error_message(RuntimeError("handshake failure"))
        self.assertEqual(message, "kesalahan SSL: handshake failure")


def first_certificate_der():
    with open(requests.certs.where(), "r", encoding="ascii") as handle:
        bundled = handle.read()
    start = bundled.index("-----BEGIN CERTIFICATE-----")
    end = bundled.index("-----END CERTIFICATE-----", start)
    end += len("-----END CERTIFICATE-----")
    return ssl.PEM_cert_to_DER_cert(bundled[start:end])


class CaBundleTests(unittest.TestCase):
    def test_merge_adds_custom_bundle_to_builtin_ca(self):
        merged = scanner.merge_ca_bundle(requests.certs.where())
        try:
            with open(merged, "rb") as handle:
                content = handle.read()
            with open(requests.certs.where(), "rb") as handle:
                bundled = handle.read()
            self.assertGreater(len(content), len(bundled))
            self.assertIn(b"-----BEGIN CERTIFICATE-----", content)
        finally:
            os.unlink(merged)

    def test_non_pem_bundle_is_rejected(self):
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        try:
            handle.write(b"not a certificate")
            handle.close()
            with self.assertRaises(ValueError):
                scanner.merge_ca_bundle(handle.name)
        finally:
            handle.close()
            os.unlink(handle.name)


class SystemCaTests(unittest.TestCase):
    def test_system_store_is_written_as_pem_bundle(self):
        context = mock.Mock()
        context.get_ca_certs.return_value = [first_certificate_der()]
        with mock.patch.object(
            scanner.ssl, "create_default_context", return_value=context
        ):
            bundle = scanner.build_system_ca_bundle()
        try:
            with open(bundle, "rb") as handle:
                content = handle.read()
            self.assertIn(b"-----BEGIN CERTIFICATE-----", content)
        finally:
            os.unlink(bundle)

    def test_empty_system_store_is_rejected(self):
        context = mock.Mock()
        context.get_ca_certs.return_value = []
        with mock.patch.object(
            scanner.ssl, "create_default_context", return_value=context
        ):
            with self.assertRaises(ValueError):
                scanner.build_system_ca_bundle()


def fingerprint():
    return {
        "baseline_url": "https://target.test/",
        "status_code": 200,
        "server": "nginx",
        "powered_by": None,
        "tech": ["NGINX"],
        "tech_details": [],
        "tech_summary": "NGINX=terdeteksi",
        "router_version": None,
        "waf": [],
        "challenge": False,
        "blocked": False,
        "headers": {},
        "reason": None,
        "error": None,
        "timestamp": "2026-10-26T00:00:00Z",
    }


def php_finding():
    return {
        "engine": "php",
        "cve": scanner.PHP_CVES,
        "host": "https://target.test",
        "vulnerable": None,
        "verdict": "INCONCLUSIVE",
        "status_code": 500,
        "error": None,
        "reason": None,
        "skipped": False,
        "skip_reason": None,
    }


class ScanHostTlsTests(unittest.TestCase):
    def test_custom_ca_path_is_forwarded_to_baseline_and_engine(self):
        with (
            mock.patch.object(
                scanner, "collect_fingerprint", return_value=fingerprint()
            ) as collect,
            mock.patch.object(
                scanner, "php_check_vulnerability", return_value=php_finding()
            ) as php,
        ):
            scanner.scan_host(
                host="https://target.test",
                mode="php",
                timeout=5,
                verify_ssl="custom-ca.pem",
                custom_headers={},
                sapi="auto",
                paths=None,
                safe_check=True,
                windows=False,
                waf_bypass=False,
                waf_bypass_size_kb=128,
                vercel_waf_bypass=False,
            )

        collect.assert_called_once_with(
            "https://target.test", 5, "custom-ca.pem", {}
        )
        self.assertEqual(php.call_args.kwargs["verify_ssl"], "custom-ca.pem")

    def test_baseline_failure_does_not_use_probe_status(self):
        failed = fingerprint()
        failed["status_code"] = None
        failed["error"] = "verifikasi TLS gagal"
        finding = php_finding()
        finding["status_code"] = 403
        with (
            mock.patch.object(
                scanner, "collect_fingerprint", return_value=failed
            ),
            mock.patch.object(
                scanner, "php_check_vulnerability", return_value=finding
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

        self.assertIsNone(result["status_code"])
        self.assertIn("baseline gagal", result["reason"])

    def test_custom_ca_for_php_keeps_verification_enabled(self):
        context = scanner.php_ssl_context(requests.certs.where())
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)


if __name__ == "__main__":
    unittest.main()
