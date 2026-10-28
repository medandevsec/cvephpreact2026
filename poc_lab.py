"""Lab PoC e2e - menjalankan PoC setiap CVE secara mandiri.

Lab ini memunculkan target lokal (fixture) yang mereplikasi kondisi
rentan, lalu menjalankan engine scanner dengan PoC-nya, dan menampilkan
verdict beserta bukti ringkas. Gunakan --fixed untuk membandingkan
dengan skenario versi yang sudah dipatch, dan --json untuk menyimpan
hasil mentah.

Contoh:
    python poc_lab.py php
    python poc_lab.py react
    python poc_lab.py chain
    python poc_lab.py all --fixed
    python poc_lab.py nginx --json hasil_lab.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable, Dict, List

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import scanner
import poc_chain
from e2e_support import FixtureTarget, Scenario

BASE_OPTIONS = {
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


def _opts(**overrides) -> Dict:
    options = dict(BASE_OPTIONS)
    options.update(overrides)
    return options


def _first_finding(result: Dict) -> Dict:
    findings = result.get("findings") or [{}]
    return findings[0]


def _ev_verdict(result: Dict, target) -> List[str]:
    return [f"verdict   : {result.get('verdict')}"]


def _ev_php(result: Dict, target) -> List[str]:
    finding = _first_finding(result)
    return _ev_verdict(result, target) + [
        f"sapi      : {finding.get('sapi')}",
        f"request   : {target.state.count('POST')} POST",
        f"alasan    : {finding.get('reason')}",
    ]


def _ev_react_safe(result: Dict, target) -> List[str]:
    finding = _first_finding(result)
    return _ev_verdict(result, target) + [
        f"verdict   : {finding.get('verdict')} (temuan)",
        f"alasan    : {finding.get('reason')}",
    ]


def _ev_react_rce(result: Dict, target) -> List[str]:
    finding = _first_finding(result)
    return _ev_verdict(result, target) + [
        f"verdict   : {finding.get('verdict')} (temuan)",
        f"bukti     : {finding.get('response')}",
    ]


def _ev_chain(result: Dict, target) -> List[str]:
    finding = _first_finding(result)
    stages = finding.get("stages") or []
    stage_summary = " | ".join(
        f"{stage.get('name')}={'OK' if stage.get('ok') else 'GAGAL'}"
        for stage in stages
    )
    return _ev_verdict(result, target) + [
        f"shell     : {finding.get('shell')}",
        f"tahap     : {stage_summary}",
        f"alasan    : {finding.get('reason')}",
    ]


def _chain_runner(target_url: str, options: Dict) -> Dict:
    return poc_chain.run_chain(
        target_url,
        timeout=options.get("timeout", 5),
        verify_ssl=options.get("verify_ssl", True),
    )


def _ev_router(result: Dict, target) -> List[str]:
    framework = _first_finding(result).get("framework") or {}
    return _ev_verdict(result, target) + [
        f"versi     : {framework.get('version')}",
        f"affected  : {framework.get('affected')}",
        f"manifest  : {framework.get('manifest_checked')}",
        "catatan   : CVE-2026-42211 sengaja pasif; eksploitasi butuh",
        "            prototype pollution pada aplikasi target.",
    ]


def _ev_node(result: Dict, target) -> List[str]:
    finding = _first_finding(result)
    return _ev_verdict(result, target) + [
        f"kontrol   : lulus={finding.get('control_passed')}",
        f"bukti     : {finding.get('response')}",
        f"alasan    : {finding.get('reason')}",
    ]


def _ev_nginx(result: Dict, target) -> List[str]:
    finding = _first_finding(result)
    return _ev_verdict(result, target) + [
        f"kontrol   : lulus={finding.get('control_passed')}",
        f"pemulihan : liveness_recovered={finding.get('liveness_recovered')}",
        f"alasan    : {finding.get('reason')}",
    ]


def _ev_nginx_version(result: Dict, target) -> List[str]:
    finding = _first_finding(result)
    return _ev_verdict(result, target) + [
        f"alasan    : {finding.get('reason')}",
    ]


class Case:
    def __init__(
        self,
        label: str,
        scenario,
        options: Dict,
        expected: str,
        evidence: Callable[[Dict, object], List[str]],
        fixed_scenario=None,
        fixed_expected: str = "NOT VULNERABLE",
        runner: Callable[[str, Dict], Dict] = None,
    ) -> None:
        self.label = label
        self.scenario = scenario
        self.options = options
        self.expected = expected
        self.evidence = evidence
        self.fixed_scenario = fixed_scenario
        self.fixed_expected = fixed_expected
        self.runner = runner


ENGINES: Dict[str, Dict] = {
    "php": {
        "cve": "CVE-2026-109618 / CVE-2026-109619",
        "title": "PHP multipart parsing (probe crash + diferensial)",
        "cases": [
            Case(
                "PoC crash + kontrol valid",
                Scenario(php="crash"),
                _opts(mode="php"),
                "VULNERABLE",
                _ev_php,
                fixed_scenario=Scenario(php="fixed"),
            ),
        ],
    },
    "react": {
        "cve": "CVE-2025-55182 / CVE-2025-66478",
        "title": "React Server Components / Next.js RCE",
        "cases": [
            Case(
                "Side-channel aman",
                Scenario(react="safe-vulnerable"),
                _opts(mode="react"),
                "VULNERABLE",
                _ev_react_safe,
                fixed_scenario=Scenario(react="safe-fixed"),
            ),
            Case(
                "PoC RCE (payload Next Redirect)",
                Scenario(react="rce-vulnerable"),
                _opts(mode="react", safe_check=False),
                "VULNERABLE",
                _ev_react_rce,
                fixed_scenario=Scenario(react="safe-fixed"),
            ),
        ],
    },
    "react-router": {
        "cve": "CVE-2026-42211",
        "title": "React Router Framework Mode (deteksi versi pasif)",
        "cases": [
            Case(
                "Deteksi versi pasif",
                Scenario(react_router="affected"),
                _opts(mode="react-router"),
                "INCONCLUSIVE",
                _ev_router,
                fixed_scenario=Scenario(react_router="fixed"),
            ),
        ],
    },
    "nodejs": {
        "cve": "CVE-2026-111497",
        "title": "Node.js Brotli decoder (PoC diferensial)",
        "cases": [
            Case(
                "PoC Brotli (kontrol negatif + vektor malformed)",
                Scenario(node_passive=True, node_poc="vulnerable"),
                _opts(mode="nodejs", nodejs_poc=True),
                "VULNERABLE",
                _ev_node,
                fixed_scenario=Scenario(
                    node_passive=True, node_poc="patched"
                ),
            ),
        ],
    },
    "nginx": {
        "cve": "CVE-2026-42945",
        "title": "NGINX rewrite_module (probe overflow)",
        "cases": [
            Case(
                "Deteksi versi pasif",
                Scenario(nginx="affected"),
                _opts(mode="nginx"),
                "INCONCLUSIVE",
                _ev_nginx_version,
                fixed_scenario=Scenario(nginx="fixed"),
            ),
            Case(
                "PoC probe overflow (kontrol + liveness)",
                Scenario(nginx="poc-vulnerable"),
                _opts(mode="nginx", nginx_poc=True),
                "VULNERABLE",
                _ev_nginx,
                fixed_scenario=Scenario(nginx="poc-patched"),
                fixed_expected="INCONCLUSIVE",
            ),
        ],
    },
    "chain": {
        "cve": poc_chain.CHAIN_CVES,
        "title": "Rantai e2e RCE -> webshell (upload -> serve -> exec -> cleanup)",
        "cases": [
            Case(
                "Rantai RCE -> webshell 4 tahap",
                Scenario(react="rce-upload"),
                _opts(),
                "VULNERABLE",
                _ev_chain,
                fixed_scenario=Scenario(react="rce-fixed"),
                runner=_chain_runner,
            ),
        ],
    },
}

CASE_LABEL_WIDTH = 44


def run_case(case: Case, show_fixed: bool) -> Dict:
    def _run(target_url: str) -> Dict:
        if case.runner is not None:
            return case.runner(target_url, case.options)
        return scanner.scan_host(target_url, **case.options)

    with FixtureTarget(case.scenario) as target:
        result = _run(target.url)
        evidence = case.evidence(result, target)

    print(f"    {case.label:<{CASE_LABEL_WIDTH}}", end="")
    verdict = result.get("verdict")
    match = verdict == case.expected
    print(f"-> {verdict} [{'OK' if match else 'TIDAK SESUAI (harusnya ' + case.expected + ')'}]")

    for line in evidence:
        print(f"        {line}")

    if show_fixed and case.fixed_scenario is not None:
        with FixtureTarget(case.fixed_scenario) as target:
            fixed_result = _run(target.url)
            fixed_evidence = case.evidence(fixed_result, target)

        print(f"    {'(pembanding) versi sudah dipatch':<{CASE_LABEL_WIDTH}}", end="")
        fixed_verdict = fixed_result.get("verdict")
        fixed_expected = case.fixed_expected
        fixed_match = fixed_verdict == fixed_expected
        print(
            f"-> {fixed_verdict} "
            f"[{'OK' if fixed_match else 'TIDAK SESUAI (harusnya ' + fixed_expected + ')'}]"
        )
        for line in fixed_evidence:
            print(f"        {line}")

    return result


def run_engine(engine_key: str, show_fixed: bool, collect: Dict) -> bool:
    spec = ENGINES[engine_key]
    print()
    print(f"=== {engine_key.upper()} | {spec['cve']} ===")
    print(f"    {spec['title']}")
    collect[engine_key] = {}
    ok = True
    for case in spec["cases"]:
        try:
            result = run_case(case, show_fixed)
            collect[engine_key][case.label] = result
            verdict = result.get("verdict")
            if verdict != case.expected:
                ok = False
        except Exception as exc:  # pragma: no cover - diagnostic path
            ok = False
            print(f"    {case.label:<{CASE_LABEL_WIDTH}} -> ERROR: {exc}")
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Lab PoC e2e untuk semua CVE yang didukung scanner."
    )
    parser.add_argument(
        "engine",
        nargs="?",
        default="all",
        choices=[*ENGINES.keys(), "all"],
        help="Engine/CVE yang dijalankan (default: all)",
    )
    parser.add_argument(
        "--fixed",
        action="store_true",
        help="Jalankan juga skenario pembanding versi sudah-dipatch",
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

    keys = list(ENGINES.keys()) if args.engine == "all" else [args.engine]

    collect: Dict[str, Dict] = {}
    failures = []
    for key in keys:
        if not run_engine(key, args.fixed, collect):
            failures.append(key)

    print()
    if failures:
        print(f"HASIL LAB: {len(failures)} engine tidak sesuai ekspektasi: {', '.join(failures)}")
        exit_code = 1
    else:
        total = sum(len(cases) for cases in (ENGINES[k]["cases"] for k in keys))
        print(f"HASIL LAB: semua PoC berjalan sesuai ekspektasi ({total} kasus).")
        exit_code = 0

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(collect, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"Hasil mentah tersimpan: {args.json_path}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
