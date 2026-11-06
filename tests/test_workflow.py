"""GitHub Actions 워크플로 점검 — v3 PR 6.

실제 실행은 GitHub 에서만 볼 수 있으므로, "검사가 빠지거나 게이트가 약해지는" 변경을 여기서 막는다.
YAML 라이브러리를 새로 설치하지 않도록 글자 단위로 확인한다 (requirements.txt 는 python-hcl2 하나).
문법 자체는 actionlint 1.7.7 로 따로 확인했다 (docs/TEST_REPORT.md).
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github" / "workflows" / "policy-gate.yml").read_text(encoding="utf-8")


def section(start_pattern, text=WORKFLOW):
    """start_pattern 줄부터, 같은 들여쓰기 이하의 다음 키가 나오기 전까지."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.match(start_pattern, line):
            indent = len(line) - len(line.lstrip())
            body = [line]
            for nxt in lines[i + 1:]:
                if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= indent and not nxt.lstrip().startswith("#"):
                    break
                body.append(nxt)
            return "\n".join(body)
    raise AssertionError(f"없음: {start_pattern}")


def job(key):
    return section(rf"^  {re.escape(key)}:\s*$")


class TriggerTest(unittest.TestCase):
    def test_pull_request_has_no_paths_filter(self):
        # paths 가 있으면 README 만 바꾼 PR 에서 필수 검사가 생성되지 않아 "대기 중"으로 남는다
        pr = section(r"^  pull_request:")
        self.assertNotIn("paths", pr)

    def test_push_paths_cover_every_checked_input(self):
        push = section(r"^  push:")
        listed = set(re.findall(r'-\s*"([^"]+)"', push))
        needed = {"infra/**", "samples/**", "scenarios/**", "tools/**", "tests/**", "requirements.txt",
                  ".github/workflows/policy-gate.yml"}
        needed |= {p.name for p in ROOT.glob("*.py")}
        self.assertEqual(needed - listed, set())


class JobTest(unittest.TestCase):
    def test_required_job_names_unchanged(self):
        # 브랜치 보호의 필수 검사 이름. 바꾸면 PR 이 영원히 "대기 중"
        self.assertIn("name: 1. 보안 정책 검사", job("policy-gate"))
        self.assertIn("name: 2. 모의 배포", job("mock-deploy"))
        self.assertIn("name: 3. 멀티클라우드 통합 검증", job("scenario-summary"))

    def test_policy_gate_runs_tests_selftest_and_infra(self):
        gate = job("policy-gate")
        for command in ("python -m unittest discover -s tests", "python self_test.py",
                        "python policy_gate.py infra --json results.json", "python summary.py results.json"):
            with self.subTest(command):
                self.assertIn(command, gate)

    def test_mock_deploy_depends_on_gate(self):
        self.assertRegex(job("mock-deploy"), r"needs:\s*policy-gate")

    def test_scenario_matrix_matches_scenario_folders(self):
        scenario = job("scenario")
        listed = re.search(r"scenario:\s*\[([^\]]*)\]", scenario).group(1)
        names = {n.strip() for n in listed.split(",")}
        folders = {p.name for p in (ROOT / "scenarios").iterdir() if p.is_dir()}
        self.assertEqual(names, folders)
        self.assertIn("fail-fast: false", scenario)

    def test_scenario_gate_and_deploy_steps(self):
        scenario = job("scenario")
        gate = section(r"^      - name: 정책 게이트", scenario)
        self.assertIn("id: gate", gate)
        self.assertIn("continue-on-error: true", gate)
        self.assertIn('echo "$code" > gate-exit.txt', gate)
        deploy = section(r"^      - name: 모의 배포", scenario)
        self.assertIn("id: deploy", deploy)
        self.assertIn("if: steps.gate.outcome == 'success'", deploy)
        verify = section(r"^      - name: 기대 동작 확인", scenario)
        self.assertIn("if: always()", verify)
        self.assertIn("steps.gate.outcome", verify)
        self.assertIn("steps.deploy.outcome", verify)

    def test_aggregate_job_always_runs_after_matrix(self):
        summary = job("scenario-summary")
        self.assertRegex(summary, r"needs:\s*scenario\s*\n")
        self.assertRegex(summary, r"\n    if: always\(\)")
        self.assertIn('--needs-result "${{ needs.scenario.result }}"', summary)
        self.assertNotIn("continue-on-error: true\n        run:", summary)   # 최종 판정 단계는 실패를 숨기지 않음


class ActionVersionTest(unittest.TestCase):
    """Node.js 24 대응 (v3 PR 6 C1). GitHub 은 2026-09-23 에 러너에서 Node 20 을 제거했다.
    아래 버전은 각 태그의 action.yml 이 runs.using: node24 인 것을 저장소에서 직접 확인했다
    (upload-artifact v5, download-artifact v5·v6 은 아직 node20 이라 건너뜀)."""
    NODE24 = {"actions/checkout@v5", "actions/setup-python@v6", "actions/upload-artifact@v6",
              "actions/download-artifact@v7"}

    def test_every_action_is_a_node24_version(self):
        used = set(re.findall(r"uses:\s*(\S+)", WORKFLOW))
        self.assertTrue(used)
        self.assertEqual(used - self.NODE24, set())


if __name__ == "__main__":
    unittest.main()
