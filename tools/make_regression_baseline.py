"""PR 5 최종 결과를 회귀 기준 파일로 고정한다 (PR 6 A1 커밋에서 코드 수정 전에 한 번 실행).

실행: python tools/make_regression_baseline.py > tests/fixtures/pr5_regression_baseline.json
- files  : samples/ 의 .tf 파일마다 따로 검사한 결과 (self_test·CLI 파일 단위와 같은 경로)
- folders: infra/, samples/ 와 그 하위 폴더를 통째로 검사한 결과
- exit   : 위 폴더를 CLI 로 검사했을 때의 종료 코드
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from policy_gate import scan_paths  # noqa: E402

FOLDERS = ["infra", "samples", "samples/safe", "samples/risky", "samples/review", "samples/error"]


def rel(results):
    for r in results:
        r["file"] = Path(r["file"]).resolve().relative_to(ROOT).as_posix()
    return results


def main():
    files = {}
    for path in sorted((ROOT / "samples").rglob("*.tf")):
        result = rel(scan_paths([path]))[0]
        files[result["file"]] = result
    folders, codes = {}, {}
    for folder in FOLDERS:
        paths = sorted((ROOT / folder).rglob("*.tf"))
        folders[folder] = rel(scan_paths(paths))
        codes[folder] = subprocess.run([sys.executable, "policy_gate.py", folder], cwd=ROOT,
                                       capture_output=True, text=True).returncode
    json.dump({"files": files, "folders": folders, "exit": codes}, sys.stdout,
              ensure_ascii=False, indent=1, sort_keys=True)
    print()


if __name__ == "__main__":
    main()
