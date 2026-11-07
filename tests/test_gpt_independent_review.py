"""GPT 독립 회귀 테스트 12개를 원본 그대로 전체 단위 테스트에 포함 — v3.2.2.

tests/independent/ 의 두 파일은 GPT 가 보낸 파일과 바이트 단위로 같아야 한다 (SHA-256 으로 확인).
두 파일은 이름이 test*.py 가 아니라 discover 가 찾지 못하므로 load_tests 로 불러온다.
python-hcl2 없이 실행된다 (파싱된 딕셔너리를 바로 넣음).
실행: python -m unittest discover -s tests -v
"""
import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

ORIGINALS = {  # GPT 재검토 묶음(CloudGuard_GPT_regression_tests_bundle.zip)의 원본 해시
    "cloudguard_v32_gpt_regression_tests.py":
        "3e412ab23051519a641a30dbe917f4b312abe2e276816eafd85d6ce3c8d8f10d",
    "cloudguard_v321_gpt_new_regressions.py":
        "a3ff4e7b20783147235fbe4a58896c54b2c383de07ded8a25bc44224eeee785b",
}


class UnmodifiedTest(unittest.TestCase):
    def test_files_are_byte_identical_to_gpt_originals(self):
        for name, digest in ORIGINALS.items():
            with self.subTest(name):
                data = (HERE / "independent" / name).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), digest)


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(UnmodifiedTest))
    for name in ORIGINALS:
        spec = importlib.util.spec_from_file_location(name[:-3], HERE / "independent" / name)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        suite.addTests(loader.loadTestsFromModule(module))
    return suite
