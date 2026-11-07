"""v3.2.1 GPT 재검토 지적 D·B·C 회귀 테스트 — v3.2.2 (python-hcl2 없이 실행, 파싱된 딕셔너리 입력).

D. 단조성: 확정 규칙만으로 인터넷 전체가 되어 BLOCK 이면, 어떤 규칙을 더해도 BLOCK 이 사라지거나
   REVIEW·PASS 로 낮아지면 안 된다. (v3.2.1: 포트가 변수인 0.0.0.0/0 규칙을 더하면 BLOCK → REVIEW)
B. 원인 표시: 표시된 규칙만 합쳐도 인터넷 전체가 되어야 하고(충분), 이미 덮인 대역 규칙은 표시하지 않는다.
   무작위로 만든 대역 묶음에서 '최소 충분 집합에 들어가는 규칙'과 정확히 같은지 전수 조사로 확인한다.
C. 교차 폴더: 한 폴더가 혼자 이미 전체를 덮으면, 다른 폴더의 작은 규칙 때문에 REVIEW 를 만들지 않는다.
   서로 다른 폴더의 절반 두 개(합쳐야 전체)는 계속 REVIEW.
실행: python -m unittest discover -s tests -v
"""
import itertools
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from policy_gate import (add_cross_folder_aws_union, cidr_network, file_status,  # noqa: E402
                         make_aws_context, networks_cover_internet, scan_configuration)

WEB = "${aws_security_group.web.id}"
RANK = {"PASS": 0, "REVIEW": 1, "BLOCK": 2, "ERROR": 3}


def rule(name, cidr, *, sg=WEB, proto="tcp", from_port=22, to_port=22, v6=False):
    body = {"security_group_id": sg, "ip_protocol": proto, ("cidr_ipv6" if v6 else "cidr_ipv4"): cidr}
    if proto != "-1":
        body.update(from_port=from_port, to_port=to_port)
    return {"aws_vpc_security_group_ingress_rule": {name: body}}


def legacy(name, cidrs, *, sg=WEB, kind="ingress", proto="tcp", port=22):
    return {"aws_security_group_rule": {name: {"type": kind, "security_group_id": sg, "protocol": proto,
                                               "from_port": port, "to_port": port, "cidr_blocks": cidrs}}}


def scan(*resources):
    findings = scan_configuration({"resource": list(resources)})
    return findings, file_status(findings)


def blocked(findings):
    return {f["resource"] for f in findings if f["verdict"] == "BLOCK"}


BASES = {
    "vpc 규칙 절반 2개": [rule("a", "0.0.0.0/1"), rule("b", "128.0.0.0/1")],
    "security_group_rule 절반 2개": [legacy("a", ["0.0.0.0/1"]), legacy("b", ["128.0.0.0/1"])],
    "세 조각": [rule("a", "0.0.0.0/2"), rule("b", "64.0.0.0/2"), rule("c", "128.0.0.0/1")],
    "IPv6 절반 2개": [rule("a", "::/1", v6=True), rule("b", "8000::/1", v6=True)],
    "-1 절반 + tcp 절반": [rule("a", "0.0.0.0/1", proto="-1"), rule("b", "128.0.0.0/1")],
}

EXTRAS = {
    "포트가 변수인 0.0.0.0/0 (GPT 반례)": rule("x", "0.0.0.0/0", from_port="${var.min}", to_port="${var.max}"),
    "대상 불명 0.0.0.0/0": rule("x", "0.0.0.0/0", sg="${var.sg}"),
    "프로토콜 변수 0.0.0.0/0": rule("x", "0.0.0.0/0", proto="${var.p}"),
    "방향 불명 0.0.0.0/0": legacy("x", ["0.0.0.0/0"], kind="${var.t}"),
    "출발지 변수": rule("x", "${var.cidr}"),
    "대상 불명 절반": rule("x", "128.0.0.0/1", sg="${var.sg}"),
    "포트 변수 절반": rule("x", "0.0.0.0/1", from_port="${var.p}", to_port="${var.p}"),
    "udp 0.0.0.0/0": rule("x", "0.0.0.0/0", proto="udp"),
    "icmp 0.0.0.0/0": rule("x", "0.0.0.0/0", proto="icmp", from_port=-1, to_port=-1),
    "egress 0.0.0.0/0": legacy("x", ["0.0.0.0/0"], kind="egress"),
    "다른 보안그룹 0.0.0.0/0": rule("x", "0.0.0.0/0", sg="${aws_security_group.db.id}"),
    "사설 10.0.0.0/8": rule("x", "10.0.0.0/8"),
    "8.8.8.0/24": rule("x", "8.8.8.0/24"),
    "443 0.0.0.0/0": rule("x", "0.0.0.0/0", from_port=443, to_port=443),
    "확정 0.0.0.0/0": rule("x", "0.0.0.0/0"),
}


class MonotonicBlockTest(unittest.TestCase):
    """D. 확정 BLOCK 은 규칙을 더해도 사라지지 않는다."""

    def test_extra_rules_never_remove_definite_block(self):
        for base_name, base in BASES.items():
            base_findings, base_status = scan(*base)
            self.assertEqual(base_status, "BLOCK", base_name)
            base_blocked = blocked(base_findings)
            for extra_name, extra in EXTRAS.items():
                with self.subTest(base=base_name, extra=extra_name):
                    findings, status = scan(*base, extra)
                    self.assertEqual(status, "BLOCK")
                    self.assertTrue(base_blocked <= blocked(findings), (base_blocked, blocked(findings)))

    def test_extra_rule_grid(self):
        """더하는 규칙을 격자로 전부: 출발지 6 × 대상 3 × 포트 3 × 프로토콜 4 = 216가지 × 기본 BLOCK 5가지."""
        grid = itertools.product(["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "10.0.0.0/8", "8.8.8.0/24", "${var.c}"],
                                 [WEB, "${var.sg}", "${aws_security_group.db.id}"],
                                 [22, "${var.p}", 443],
                                 ["tcp", "-1", "udp", "${var.proto}"])
        extras = [rule("x", c, sg=sg, proto=pr, from_port=po, to_port=po) for c, sg, po, pr in grid]
        for base_name, base in BASES.items():
            base_blocked = blocked(scan(*base)[0])
            for extra in extras:
                body = extra["aws_vpc_security_group_ingress_rule"]["x"]
                with self.subTest(base=base_name, extra=body):
                    findings, status = scan(*base, extra)
                    self.assertEqual(status, "BLOCK")
                    self.assertTrue(base_blocked <= blocked(findings))

    def test_two_extra_rules_together(self):
        base = BASES["vpc 규칙 절반 2개"]
        base_blocked = blocked(scan(*base)[0])
        for (n1, e1), (n2, e2) in itertools.combinations(EXTRAS.items(), 2):
            e2 = {typ: {f"{name}2": body for name, body in bodies.items()} for typ, bodies in e2.items()}
            with self.subTest(n1, n2=n2):
                findings, status = scan(*base, e1, e2)
                self.assertEqual(status, "BLOCK")
                self.assertTrue(base_blocked <= blocked(findings))

    def test_random_rule_sets_file_verdict_never_decreases(self):
        """무작위 규칙 목록에 규칙을 하나 더해도 파일 판정 순위(PASS<REVIEW<BLOCK)가 내려가지 않는다."""
        rng = random.Random(20261107)
        pool = ["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2",
                "192.0.0.0/2", "10.0.0.0/8", "8.8.8.0/24", "${var.c}"]
        targets = [WEB, "${var.sg}", "${aws_security_group.db.id}", "sg-1"]
        ports = [22, 3389, 443, "${var.p}"]
        protos = ["tcp", "tcp", "-1", "udp", "${var.proto}"]

        def random_rule(i):
            port = rng.choice(ports)
            return rule(f"r{i}", rng.choice(pool), sg=rng.choice(targets), proto=rng.choice(protos),
                        from_port=port, to_port=port)

        for trial in range(300):
            rules = [random_rule(i) for i in range(rng.randint(1, 6))]
            extra = random_rule(99)
            with self.subTest(trial=trial):
                before = scan(*rules)[1]
                after = scan(*rules, extra)[1]
                self.assertGreaterEqual(RANK[after], RANK[before], (rules, extra))


def brute_force_relevant(unit_nets):
    """최소 충분 집합(어느 원소도 뺄 수 없는 덮개)에 한 번이라도 들어가는 원소의 번호 — 전수 조사."""
    n = len(unit_nets)
    covers = lambda idx: networks_cover_internet([x for i in idx for x in unit_nets[i]])  # noqa: E731
    members = set()
    for size in range(1, n + 1):
        for subset in itertools.combinations(range(n), size):
            if covers(subset) and all(not covers([j for j in subset if j != i]) for i in subset):
                members.update(subset)
    return members


class WitnessTest(unittest.TestCase):
    """B. 표시된 규칙 = 최소 충분 집합에 들어가는 규칙 (충분하고, 이미 덮인 규칙은 제외)."""

    def entries(self, cidr_lists):
        return [{"ref": f"r{i}", "nets": [cidr_network(c) for c in cidrs]} for i, cidrs in enumerate(cidr_lists)]

    def test_matches_brute_force_on_random_sets(self):
        rng = random.Random(7)
        blocks = [f"{a}.0.0.0/{p}" for p, step in ((1, 128), (2, 64), (3, 32)) for a in range(0, 256, step)]
        blocks += ["10.0.0.0/8", "8.8.8.0/24", "172.16.0.0/12"]
        checked = 0
        while checked < 150:
            cidr_lists = [rng.sample(blocks, rng.randint(1, 3)) for _ in range(rng.randint(2, 7))]
            unit_nets = [list(dict.fromkeys(cidr_network(c) for c in cl)) for cl in cidr_lists]
            if not networks_cover_internet([x for u in unit_nets for x in u]):
                continue
            entries = self.entries(cidr_lists)
            from policy_gate import _relevant_entries  # v3.2.2 에서 생긴 함수 — 수정 전 코드에서는 이 테스트만 오류
            got = {int(e["ref"][1:]) for e in _relevant_entries(entries, 4)}
            expected = brute_force_relevant(unit_nets)
            # 같은 대역을 가진 규칙은 한 묶음 — 전수 조사는 원소 단위이므로 묶음 기준으로 맞춘다
            key = lambda i: tuple(sorted(map(str, unit_nets[i])))  # noqa: E731
            expected_units = {key(i) for i in expected}
            expected = {i for i in range(len(unit_nets)) if key(i) in expected_units}
            with self.subTest(cidr_lists=cidr_lists):
                self.assertEqual(got, expected)
                self.assertTrue(networks_cover_internet([x for i in got for x in unit_nets[i]]))
            checked += 1

    def test_gpt_examples(self):
        cases = [
            (["0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2", "8.8.8.0/24"],
             {0, 1, 2, 3, 4, 5}),
            (["0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2", "10.0.0.0/8"],
             {0, 1, 2, 3, 4, 5}),
            (["0.0.0.0/1", "128.0.0.0/1", "128.0.0.0/2", "192.0.0.0/2"], {0, 1, 2, 3}),
        ]
        for cidrs, expected in cases:
            with self.subTest(cidrs):
                findings, status = scan(*(rule(f"r{i}", c) for i, c in enumerate(cidrs)))
                self.assertEqual(status, "BLOCK")
                got = {int(r.rsplit(".r", 1)[1]) for r in blocked(findings)}
                self.assertEqual(got, expected)
                self.assertTrue(networks_cover_internet([cidr_network(cidrs[i]) for i in got]))

    def test_reason_does_not_claim_a_count(self):
        """사유에 '규칙 N개' 를 쓰지 않는다 (원인 규칙이 여러 덮개에 걸칠 수 있음). 원인 규칙 이름과 대역은 적는다."""
        findings, _ = scan(rule("a", "0.0.0.0/1"), rule("b", "128.0.0.0/1"), rule("c", "128.0.0.0/2"),
                           rule("d", "192.0.0.0/2"))
        for f in findings:
            self.assertNotRegex(f["reason"], r"규칙 \d+개")
            self.assertIn("aws_vpc_security_group_ingress_rule.a 0.0.0.0/1", f["reason"])


class CrossFolderTest(unittest.TestCase):
    """C. 교차 폴더 REVIEW 는 다른 폴더끼리 합쳐야만 전체가 될 때만."""

    def contexts(self, folders):
        ctx = {Path(f): make_aws_context([{"resource": rules}], Path(f)) for f, rules in folders.items()}
        add_cross_folder_aws_union(ctx)
        return ctx

    def review_refs(self, ctx):
        return {(str(folder), ref) for c in ctx.values() for (folder, ref), items in c["union"].items()
                for r, _ in items if r == "AWS_ADMIN_PORT_UNRESOLVED"}

    def test_folder_already_full_plus_private_elsewhere(self):
        ctx = self.contexts({"/a": [rule("a", "0.0.0.0/1", sg="sg-1"), rule("b", "128.0.0.0/1", sg="sg-1")],
                             "/b": [rule("c", "10.0.0.0/8", sg="sg-1")]})
        self.assertEqual(self.review_refs(ctx), set())

    def test_folder_already_full_plus_public_piece_elsewhere(self):
        ctx = self.contexts({"/a": [rule("a", "0.0.0.0/1", sg="sg-1"), rule("b", "128.0.0.0/1", sg="sg-1")],
                             "/b": [rule("c", "8.8.8.0/24", sg="sg-1")]})
        self.assertEqual(self.review_refs(ctx), set())

    def test_halves_in_two_folders_still_review(self):
        ctx = self.contexts({"/a": [rule("a", "0.0.0.0/1", sg="sg-1")],
                             "/b": [rule("b", "128.0.0.0/1", sg="sg-1")]})
        self.assertEqual(self.review_refs(ctx), {("/a", "aws_vpc_security_group_ingress_rule.a"),
                                                 ("/b", "aws_vpc_security_group_ingress_rule.b")})

    def test_full_folder_does_not_hide_other_two_folders(self):
        """한 폴더가 혼자 전체여도, 나머지 두 폴더가 서로 합쳐 전체가 되면 그 둘은 REVIEW."""
        ctx = self.contexts({"/a": [rule("a", "0.0.0.0/1", sg="sg-1"), rule("b", "128.0.0.0/1", sg="sg-1")],
                             "/b": [rule("c", "0.0.0.0/1", sg="sg-1")],
                             "/c": [rule("d", "128.0.0.0/1", sg="sg-1")]})
        self.assertEqual(self.review_refs(ctx), {("/b", "aws_vpc_security_group_ingress_rule.c"),
                                                 ("/c", "aws_vpc_security_group_ingress_rule.d")})

    def test_cross_folder_review_names_only_needed_rules(self):
        ctx = self.contexts({"/a": [rule("a", "0.0.0.0/1", sg="sg-1"), rule("p", "10.0.0.0/8", sg="sg-1")],
                             "/b": [rule("b", "128.0.0.0/1", sg="sg-1")]})
        self.assertEqual(self.review_refs(ctx), {("/a", "aws_vpc_security_group_ingress_rule.a"),
                                                 ("/b", "aws_vpc_security_group_ingress_rule.b")})


if __name__ == "__main__":
    unittest.main()
