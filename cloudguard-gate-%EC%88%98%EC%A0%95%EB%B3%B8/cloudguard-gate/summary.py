"""policy_gate.py가 만든 results.json을 읽어서 보기 좋은 표(Markdown)로 출력합니다.

GitHub Actions에서는 이 출력이 실행 결과 화면의 "Summary"에 표로 나타납니다.
내 PC에서 확인:  py summary.py results.json
"""

import json
import sys
from pathlib import Path

ICON = {"PASS": "✅ PASS", "BLOCK": "⛔ BLOCK", "ERROR": "⚠️ ERROR"}


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results.json")
    if not path.exists():
        print("## ⚠️ 검사 결과 파일이 없습니다")
        print("보안 검사 단계가 결과를 만들기 전에 멈췄습니다. 위 로그를 확인하세요.")
        return 0

    results = json.loads(path.read_text(encoding="utf-8"))
    counts = {s: sum(r["status"] == s for r in results) for s in ICON}
    gate_ok = counts["BLOCK"] == 0 and counts["ERROR"] == 0

    print("## " + ("✅ 정책 게이트 통과" if gate_ok else "⛔ 정책 게이트 차단 — 배포 중단"))
    print()
    print(f"총 {len(results)}개 | PASS {counts['PASS']} | BLOCK {counts['BLOCK']} | ERROR {counts['ERROR']}")
    print()
    print("| 파일 | 결과 | 위반 규칙 | 이유 |")
    print("|---|---|---|---|")
    for r in results:
        if r["findings"]:
            for f in r["findings"]:
                print(f"| {r['file']} | {ICON[r['status']]} | {f['rule']} | {f['reason']} |")
        else:
            reason = r.get("error") or "-"
            print(f"| {r['file']} | {ICON[r['status']]} | - | {reason} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
