"""policy_gate.py가 만든 results.json을 읽어서 보기 좋은 표(Markdown)로 출력합니다.

GitHub Actions에서는 이 출력이 실행 결과 화면의 "Summary"에 표로 나타납니다.
내 PC에서 확인:  py summary.py results.json

v3 PR 2: REVIEW(검토 필요) 표시 추가. REVIEW도 배포 차단으로 표시합니다.
"""

import json
import sys
from pathlib import Path

ICON = {"PASS": "✅ PASS", "REVIEW": "🔍 REVIEW", "BLOCK": "⛔ BLOCK", "ERROR": "⚠️ ERROR"}


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results.json")
    if not path.exists():
        print("## ⚠️ 보안 검사 결과 파일이 없습니다")
        print("검사기 자가 점검이 실패했거나 보안 검사가 시작되기 전에 멈췄습니다. "
              "위의 자가 점검 결과와 로그를 확인하세요.")
        return 0

    results = json.loads(path.read_text(encoding="utf-8"))
    counts = {s: sum(r["status"] == s for r in results) for s in ICON}
    blocked = counts["BLOCK"] or counts["REVIEW"] or counts["ERROR"]

    print("## " + ("⛔ 정책 게이트 차단 — 배포 중단" if blocked else "✅ 정책 게이트 통과"))
    print()
    print(f"총 {len(results)}개 | PASS {counts['PASS']} | REVIEW {counts['REVIEW']} "
          f"| BLOCK {counts['BLOCK']} | ERROR {counts['ERROR']}")
    if counts["REVIEW"]:
        print()
        print("> 🔍 REVIEW = 값이 변수·표현식이거나 설정이 없어 안전한지 확인할 수 없음. "
              "안전하다고 가정하지 않고 배포를 막습니다.")
    print()
    print("| 파일 | 결과 | 위반 규칙 | 이유 |")
    print("|---|---|---|---|")
    for r in results:
        if r["findings"]:
            for f in r["findings"]:
                verdict = f.get("verdict", r["status"])
                print(f"| {r['file']} | {ICON[verdict]} | {f['rule']} | {f['reason']} |")
        else:
            reason = r.get("error") or "-"
            print(f"| {r['file']} | {ICON[r['status']]} | - | {reason} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
