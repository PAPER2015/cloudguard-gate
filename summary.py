"""policy_gate.py가 만든 results.json을 읽어서 보기 좋은 표(Markdown)로 출력합니다.

GitHub Actions에서는 이 출력이 실행 결과 화면의 "Summary"에 표로 나타납니다.
내 PC에서 확인:  py summary.py results.json

v3 PR 2: REVIEW(검토 필요) 표시 추가. REVIEW도 배포 차단으로 표시합니다.
v3 PR 3: 표 칸 안의 줄바꿈·| 문자 때문에 Markdown 표가 깨지던 문제 수정 (내용은 그대로).
v3 PR 6: 기존 표 뒤에 "정책 × 클라우드 지원 행렬"을 덧붙임 (기존 출력은 한 글자도 바꾸지 않음).
"""

import json
import sys
from pathlib import Path

def md_cell(value):
    """Markdown 표 칸 하나에 안전하게 넣는다. 내용은 바꾸지 않고 표기만 바꾼다.

    - | 는 \\| 로 (표의 칸 구분선으로 오해되지 않게)
    - 줄바꿈은 <br> 로 (한 줄이 표의 한 행이 되도록)
    """
    text = str(value).replace("\r\n", "\n").replace("\r", "\n").strip()
    text = text.replace("|", "\\|")
    return "<br>".join(line.strip() for line in text.split("\n")).strip() or "-"


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
                print(f"| {md_cell(r['file'])} | {ICON[verdict]} | {md_cell(f['rule'])} | {md_cell(f['reason'])} |")
        else:
            reason = r.get("error") or "-"
            print(f"| {md_cell(r['file'])} | {ICON[r['status']]} | - | {md_cell(reason)} |")
    print_matrix(results)
    return 0


CLOUD_LABEL = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}
RESULT_ICON = {"PASS": "✅ PASS", "REVIEW": "🔍 REVIEW", "BLOCK": "⛔ BLOCK"}


def print_matrix(results):
    """정책 × 클라우드 행렬 (v3 PR 6). PASS·N/A·미지원을 구분해서 보여 준다."""
    try:
        from policy_gate import POLICY_NAMES, policy_matrix
    except Exception as exc:   # 행렬을 못 만들어도 기존 요약은 그대로 남긴다
        print()
        print(f"> ⚠️ 정책 행렬을 만들지 못했습니다: {md_cell(exc)}")
        return
    print()
    print("### 정책 × 클라우드 지원 행렬")
    print()
    print("| 정책 | 클라우드 | 결과 | 검사한 자원 | 규칙 ID | 검사 대상 자원 종류 | 알려진 한계 |")
    print("|---|---|---|---|---|---|---|")
    for cell in policy_matrix(results):
        result = RESULT_ICON.get(cell["result"], cell["result"])
        counts = cell["counts"]
        if cell["checked"]:
            checked = (f"{cell['checked']}개 (PASS {counts['PASS']} · REVIEW {counts['REVIEW']} "
                       f"· BLOCK {counts['BLOCK']})")
        else:
            checked = "0개"
        policy = f"{cell['policy']} {POLICY_NAMES[cell['policy']]}"
        print(f"| {md_cell(policy)} | {CLOUD_LABEL[cell['cloud']]} | {md_cell(result)} | {md_cell(checked)} "
              f"| {md_cell(', '.join(cell['rules']))} | {md_cell(', '.join(cell['resources']))} "
              f"| {md_cell(cell['limits'])} |")
    print()
    print("> PASS = 지원 범위 안에서 검사한 자원에 정책 위반이 없음 (클라우드 전체가 안전하다는 보증이 아님). "
          "N/A = 지원하지만 이번 검사에 대상 자원이 없음. 미지원 = 구현이 없음. "
          "확인 불가(ERROR) = 읽지 못한 파일이 있어 대상 유무를 알 수 없음.")


if __name__ == "__main__":
    sys.exit(main())
