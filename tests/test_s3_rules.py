"""S3 정책 판정 단위 테스트 (hcl2 설치 없이도 실행 가능).

실제 .tf 파싱 및 GitHub Actions 검증을 대체하지는 않습니다.
실행: python -m unittest discover -s tests -v
"""
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_gate import scan_configuration, file_status, evaluate_s3_policy


def resource(kind, name, body):
    return {"resource": [{kind: {name: body}}]}


def block(**opts):
    return resource("aws_s3_bucket_public_access_block", "demo", {
        "bucket": "cloudguard-test", **opts,
    })


def policy(statements):
    return resource("aws_s3_bucket_policy", "demo", {
        "bucket": "cloudguard-test", "policy": json.dumps({"Version":"2012-10-17", "Statement": statements})
    })


TRUE_FLAGS = dict(block_public_acls=True, block_public_policy=True,
                  ignore_public_acls=True, restrict_public_buckets=True)


class S3RulesTest(unittest.TestCase):
    def check(self, data, status, rules):
        findings = scan_configuration(data)
        self.assertEqual(file_status(findings), status)
        self.assertEqual(sorted({f["rule"] for f in findings}), sorted(rules))

    def test_all_true(self):
        self.check(block(**TRUE_FLAGS), "PASS", [])

    def test_flag_false(self):
        self.check(block(**{**TRUE_FLAGS, "block_public_policy": False}), "BLOCK", ["AWS_S3_PUBLIC_BLOCK_OFF"])

    def test_flag_variable(self):
        self.check(block(**{**TRUE_FLAGS, "block_public_acls": "${var.block}"}), "REVIEW", ["AWS_S3_BLOCK_UNRESOLVED"])

    def test_flag_missing(self):
        d=TRUE_FLAGS.copy(); del d["block_public_acls"]
        self.check(block(**d), "REVIEW", ["AWS_S3_BLOCK_UNRESOLVED"])

    def test_false_overrides_unknown(self):
        d={**TRUE_FLAGS, "block_public_acls": False, "ignore_public_acls": "${var.unknown}"}
        self.check(block(**d), "BLOCK", ["AWS_S3_PUBLIC_BLOCK_OFF"])

    def test_deny_wildcard_pass(self):
        self.check(policy([{"Effect":"Deny","Principal":"*"}]), "PASS", [])

    def test_allow_specific_pass(self):
        self.check(policy([{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/app"}}]), "PASS", [])

    def test_allow_wildcard_block(self):
        self.check(policy([{"Effect":"Allow","Principal":"*"}]), "BLOCK", ["AWS_S3_WILDCARD_PRINCIPAL"])

    def test_allow_wildcard_in_aws_list_block(self):
        self.check(policy([{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:role/app", "*"]}}]), "BLOCK", ["AWS_S3_WILDCARD_PRINCIPAL"])

    def test_mixed_deny_and_allow_wildcard_block(self):
        self.check(policy([{"Effect":"Deny","Principal":"*"}, {"Effect":"Allow","Principal":"*"}]), "BLOCK", ["AWS_S3_WILDCARD_PRINCIPAL"])

    def test_expression_review(self):
        self.check(resource("aws_s3_bucket_policy","demo",{"bucket":"x","policy":"${jsonencode({})}"}), "REVIEW", ["AWS_S3_POLICY_UNRESOLVED"])

    def test_malformed_json_review(self):
        self.check(resource("aws_s3_bucket_policy","demo",{"bucket":"x","policy":"not-valid-json"}), "REVIEW", ["AWS_S3_POLICY_UNRESOLVED"])

    def test_json_statement_missing_review(self):
        self.check(resource("aws_s3_bucket_policy","demo",{"bucket":"x","policy":'{}'}), "REVIEW", ["AWS_S3_POLICY_UNRESOLVED"])

    def test_unknown_effect_review(self):
        self.check(policy([{"Effect":"${var.effect}", "Principal":"*"}]), "REVIEW", ["AWS_S3_POLICY_UNRESOLVED"])

    def test_known_violation_over_unknown_other_statement(self):
        self.check(policy([{"Effect":"${var.effect}", "Principal":"*"},{"Effect":"Allow", "Principal":"*"}]), "BLOCK", ["AWS_S3_WILDCARD_PRINCIPAL"])

    def test_deny_wildcard_with_condition_pass(self):
        self.check(policy([{"Effect":"Deny", "Principal":"*", "Condition":{"Bool":{"aws:SecureTransport":"false"}}}]), "PASS", [])

    def test_missing_policy_review(self):
        self.check(resource("aws_s3_bucket_policy", "demo",{"bucket":"cloudguard-test"}), "REVIEW", ["AWS_S3_POLICY_UNRESOLVED"])

if __name__ == '__main__':
    unittest.main()
