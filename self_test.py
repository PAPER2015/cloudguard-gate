"""검사기 자가 점검 (Self-Test)

실제 검사(infra/)를 하기 전에, 정답을 알고 있는 예시 파일(samples/)을 먼저 검사해서
검사기가 "제대로 작동하는지"부터 확인합니다.

왜 필요한가?
  python-hcl2 8.x에서 위험 파일 4개가 오류 없이 전부 PASS로 나온 적이 있습니다.
  검사기가 고장 나도 겉보기엔 "통과"로 보이는 것(= fail-open)이 보안 게이트에서 가장 위험합니다.
  자가 점검이 실패하면 게이트 전체를 멈춥니다.

정답표: samples/expected.json  (파일별 기대 결과와 걸려야 하는 규칙)

실행:  py self_test.py
종료 코드: 0 = 정답표와 모두 일치 / 1 = 하나라도 불일치 (검사기 고장으로 판단)
"""

import json
import os
import sys
from pathlib import Path

from policy_gate import scan_file

SAMPLES = Path(__file__).parent / "samples"
EXPECTED_FILE = SAMPLES / "expected.json"


def parser_version():
    try:
        from importlib.metadata import version
        return version("python-hcl2")
    except Exception:
        return "알 수 없음"


def run_one(path):
    """policy_gate.py와 같은 방식으로 1개 파일을 검사해서 (상태, 규칙 목록)을 돌려줍니다."""
    try:
        findings = scan_file(path)
    except Exception as exc:
        return "ERROR", [], f"{type(exc).__name__}: {exc}"
    rules = sorted({f["rule"] for f in findings})
    return ("BLOCK" if findings else "PASS"), rules, None


def main():
    expected = json.loads(EXPECTED_FILE.read_text(encoding="utf-8"))
    actual_files = {p.relative_to(SAMPLES).as_posix() for p in SAMPLES.rglob("*.tf")}

    rows = []      # (파일, 기대, 실제, 일치 여부, 설명)
    # 1) 정답표에 있는 파일을 하나씩 검사해서 비교
    for name, exp in sorted(expected.items()):
        exp_rules = sorted(exp["rules"])
        if name not in actual_files:
            rows.append((name, exp["status"], "파일 없음", False, "samples 폴더에 파일이 없습니다"))
            continue
        status, rules, error = run_one(SAMPLES / name)
        ok = status == exp["status"] and rules == exp_rules
        note = error or ""
        if not ok and not error:
            missing = sorted(set(exp_rules) - set(rules))
            extra = sorted(set(rules) - set(exp_rules))
            if missing:
                note += "놓친 규칙: " + ", ".join(missing) + " "
            if extra:
                note += "예상 밖 규칙: " + ", ".join(extra)
        rows.append((name, exp["status"], status, ok, note.strip()))

    # 2) 정답표에 없는 새 예시 파일이 있으면 실패 (정답 없이 추가된 파일 방지)
    for name in sorted(actual_files - set(expected)):
        rows.append((name, "(정답 없음)", "-", False, "expected.json에 기대 결과를 추가하세요"))

    passed = sum(ok for *_, ok, _ in rows)
    all_ok = passed == len(rows)

    # 터미널 출력
    print(f"[자가 점검] python-hcl2 {parser_version()} / 예시 {len(rows)}개")
    for name, exp, act, ok, note in rows:
        mark = "OK  " if ok else "FAIL"
        print(f"  [{mark}] {name}: 기대 {exp} / 실제 {act}" + (f"  ({note})" if note else ""))
    print(f"\n결과: {passed}/{len(rows)} 일치 → " +
          ("검사기 정상" if all_ok else "검사기 이상! 게이트를 중단합니다."))

    # GitHub Actions Summary 화면에 표로 표시
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as out:
            out.write("## " + ("🧪 검사기 자가 점검 통과" if all_ok else "🚨 검사기 자가 점검 실패 — 게이트 중단") + "\n\n")
            out.write(f"python-hcl2 {parser_version()} | 예시 {len(rows)}개 중 {passed}개 일치\n\n")
            out.write("| 예시 파일 | 기대 | 실제 | 일치 | 설명 |\n|---|---|---|---|---|\n")
            for name, exp, act, ok, note in rows:
                out.write(f"| {name} | {exp} | {act} | {'✅' if ok else '❌'} | {note or '-'} |\n")
            out.write("\n")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
