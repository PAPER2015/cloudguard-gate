"""통합 시나리오(scenarios/A~G) 기대 동작 확인 — v3 PR 6.

GitHub Actions 와 로컬 테스트가 같은 정답(scenarios/expected.json)과 같은 판정 코드를 쓴다.

사용:
  verify    : 시나리오 하나. Actions 매트릭스 작업의 마지막 단계에서 실행.
              python tools/check_scenario.py verify B_aws_risk --results gate-results.json --exit-file gate-exit.txt \\
                     --gate-outcome failure --deploy-outcome skipped --out scenario-result-B_aws_risk.json
  aggregate : 7개 결과 파일을 모아 최종 판정. Actions 작업 "3. 멀티클라우드 통합 검증" 에서 실행.
              python tools/check_scenario.py aggregate scenario-results --needs-result success
  --local-all : 내 PC 에서 7개 시나리오를 Actions 와 같은 순서로 흉내 내 확인 (게이트 실패 → 모의 배포 건너뜀).
종료 코드: 0 = 기대대로, 1 = 하나라도 다름.
Markdown 표를 표준 출력에 쓴다 (Actions 에서는 Summary 로 보냄).
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_FILE = ROOT / "scenarios" / "expected.json"
SEVERITY = {"PASS": 0, "REVIEW": 1, "BLOCK": 2, "ERROR": 3}
CELLS = [f"{c}/{p}" for c in ("aws", "azure", "gcp") for p in ("CG-NET-01", "CG-STO-01")]


def load_expected():
    data = json.loads(EXPECTED_FILE.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def observed(results, exit_code):
    """policy_gate 결과 JSON → 비교용 요약."""
    statuses = [r["status"] for r in results] or ["ERROR"]
    cells = {}
    for key in CELLS:
        cloud, policy = key.split("/")
        checks = [c["status"] for r in results for c in r.get("checks", [])
                  if c["cloud"] == cloud and c["policy"] == policy]
        cells[key] = max(checks, key=SEVERITY.get) if checks else "N/A"
    return {"status": max(statuses, key=SEVERITY.get), "exit": exit_code,
            "rules": sorted({f["rule"] for r in results for f in r["findings"]}), "cells": cells}


def compare(name, expected, seen, gate_outcome, deploy_outcome):
    """문제 목록 (비어 있으면 기대대로)."""
    problems = []
    for key in ("status", "exit", "rules", "cells"):
        if seen.get(key) != expected[key]:
            problems.append(f"{key}: 기대 {expected[key]} / 실제 {seen.get(key)}")
    want_gate, want_deploy = ("success", "success") if expected["deploy"] else ("failure", "skipped")
    if gate_outcome != want_gate:
        problems.append(f"게이트 단계: 기대 {want_gate} / 실제 {gate_outcome}")
    if deploy_outcome != want_deploy:
        problems.append(f"모의 배포 단계: 기대 {want_deploy} / 실제 {deploy_outcome}")
    return problems


def verify(name, results_path, exit_code, gate_outcome, deploy_outcome):
    expected = load_expected().get(name)
    if expected is None:
        return {"scenario": name, "ok": False, "problems": [f"정답표에 없는 시나리오: {name}"]}
    try:
        results = json.loads(Path(results_path).read_text(encoding="utf-8"))
    except Exception as exc:  # 결과 파일이 없으면 기대대로라고 볼 수 없다
        results = []
        if expected["status"] != "ERROR" or exit_code != 2:
            return {"scenario": name, "ok": False, "problems": [f"결과 JSON 을 읽지 못함: {exc}"]}
    seen = observed(results, exit_code)
    problems = compare(name, expected, seen, gate_outcome, deploy_outcome)
    return {"scenario": name, "ok": not problems, "problems": problems, "gate_outcome": gate_outcome,
            "deploy_outcome": deploy_outcome, "status": seen["status"], "exit": exit_code,
            "rules": seen["rules"], "cells": seen["cells"], "expected_deploy": expected["deploy"]}


def aggregate(results, needs_result):
    """7개 결과 → (ok, 문제 목록). 매트릭스 실패·누락·초과도 실패로 본다."""
    problems = []
    if needs_result != "success":
        problems.append(f"매트릭스 작업 결과가 success 가 아님: {needs_result}")
    expected = set(load_expected())
    # 시나리오마다 결과가 정확히 하나씩 있어야 한다 (set 으로 비교하면 중복이 사라져 잘못 통과함)
    counts = {}
    for r in results:
        counts[r.get("scenario")] = counts.get(r.get("scenario"), 0) + 1
    for missing in sorted(expected - set(counts)):
        problems.append(f"결과 없음(실행되지 않았거나 업로드 실패): {missing}")
    for extra in sorted(set(counts) - expected, key=str):
        problems.append(f"정답표에 없는 결과: {extra}")
    for name in sorted(n for n in expected if counts.get(n, 0) > 1):
        problems.append(f"같은 시나리오 결과가 {counts[name]}개: {name} (정확히 하나여야 함)")
    for r in results:
        if not r.get("ok"):
            problems.append(f"{r.get('scenario')}: " + "; ".join(r.get("problems", [])))
    return not problems, problems


def table(rows):
    lines = ["| 시나리오 | 판정 | 종료 코드 | 게이트 단계 | 모의 배포 단계 | 기대대로 |", "|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda x: x.get("scenario", "")):
        lines.append(f"| {r.get('scenario')} | {r.get('status', '-')} | {r.get('exit', '-')} | "
                     f"{r.get('gate_outcome', '-')} | {r.get('deploy_outcome', '-')} | {'✅' if r.get('ok') else '❌'} |")
    return "\n".join(lines)


def run_local(name):
    """Actions 매트릭스 작업을 흉내: 게이트 실행 → 성공일 때만 모의 배포 → 기대 동작 확인.

    v3.2: 결과 파일은 실행마다 새로 만드는 임시 폴더에 둔다 (예전 /tmp 고정 이름은 동시 실행 시 서로 덮어씀).
    """
    with tempfile.TemporaryDirectory(prefix="cg-scenario-") as tmp:
        out = Path(tmp) / f"{name}.json"
        proc = subprocess.run([sys.executable, "policy_gate.py", f"scenarios/{name}", "--json", str(out)],
                              cwd=ROOT, capture_output=True, text=True)
        gate = "success" if proc.returncode == 0 else "failure"
        deploy = "success" if gate == "success" else "skipped"
        return verify(name, out, proc.returncode, gate, deploy)


def main(argv):
    if argv[:1] == ["verify"]:
        args = dict(zip(argv[2::2], argv[3::2]))
        exit_text = Path(args["--exit-file"]).read_text().strip() if Path(args["--exit-file"]).exists() else "-1"
        result = verify(argv[1], args["--results"], int(exit_text or -1), args["--gate-outcome"],
                        args["--deploy-outcome"] or "skipped")
        Path(args["--out"]).write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"### 통합 시나리오 {argv[1]}\n\n" + table([result]))
        for p in result["problems"]:
            print(f"- ❌ {p}")
        return 0 if result["ok"] else 1
    if argv[:1] == ["aggregate"]:
        folder = Path(argv[1])
        needs = argv[argv.index("--needs-result") + 1] if "--needs-result" in argv else "unknown"
        rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.json"))] if folder.exists() else []
        ok, problems = aggregate(rows, needs)
        print("## " + ("✅ 멀티클라우드 통합 검증 통과" if ok else "❌ 멀티클라우드 통합 검증 실패") + "\n")
        print("위험·판정 불가·문법 오류 시나리오가 **배포를 막았으면** 기대대로(✅)입니다.\n")
        print(table(rows))
        for p in problems:
            print(f"- ❌ {p}")
        return 0 if ok else 1
    if argv[:1] == ["--local-all"]:
        rows = [run_local(name) for name in load_expected()]
        ok, problems = aggregate(rows, "success")
        print(table(rows))
        for p in problems:
            print(f"- ❌ {p}")
        return 0 if ok else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
