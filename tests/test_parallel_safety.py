"""테스트·도구를 같은 PC 에서 동시에 실행해도 파일이 겹치지 않는지 — v3.2.

v3.1 까지 tests/test_integration_scenarios.py 와 tools/check_scenario.py 가 /tmp 아래 고정된 파일 이름
(cg-test-<시나리오>.json, cg-scenario-<시나리오>.json)을 써서, 두 실행이 겹치면 서로의 결과 파일을
지우거나 덮어써 가짜 실패가 날 수 있었다 (v3.1 고장 주입 중 실제로 발생).
실행: python -m unittest discover -s tests -v
"""
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXED_TMP = re.compile(r"""["']/tmp\b|Path\(\s*["']/tmp""")

try:
    import hcl2  # noqa: F401
except ImportError:  # pragma: no cover
    hcl2 = None


class NoFixedTempPathTest(unittest.TestCase):
    def test_no_hardcoded_tmp_paths(self):
        """임시 파일은 tempfile 로 만든다 (고정된 /tmp 경로 금지). 결정적으로 검사할 수 있는 부분."""
        offenders = []
        for path in sorted(list(ROOT.glob("*.py")) + list((ROOT / "tools").rglob("*.py"))
                           + list((ROOT / "tests").glob("*.py"))):
            if path.name == Path(__file__).name:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if FIXED_TMP.search(line):
                    offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
        self.assertEqual(offenders, [])


@unittest.skipIf(hcl2 is None, "python-hcl2 미설치")
class ConcurrentRunTest(unittest.TestCase):
    def test_scenario_runs_in_parallel(self):
        """시나리오 7개 흉내 실행을 동시에 4번 — 모두 성공하고 출력이 같아야 한다.
        (겹침은 타이밍에 따라 나므로 이 시험은 확률적이다. 위의 고정 경로 검사가 결정적인 확인.)"""
        procs = [subprocess.Popen([sys.executable, "tools/check_scenario.py", "--local-all"], cwd=ROOT,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(4)]
        outputs = [p.communicate(timeout=300) for p in procs]
        self.assertEqual([p.returncode for p in procs], [0, 0, 0, 0], [o[1][-500:] for o in outputs])
        self.assertEqual(len({o[0] for o in outputs}), 1)


if __name__ == "__main__":
    unittest.main()
