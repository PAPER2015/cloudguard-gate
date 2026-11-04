"""Educational Terraform policy gate (AWS/Azure/GCP).

Usage:
  py -m pip install -r requirements.txt     (python-hcl2==7.3.1)
  py policy_gate.py infra --json results.json

This is a *starter* static checker. PASS means only these selected demo rules
passed, not that a Terraform configuration is production secure.

v3 PR 1: 결과에 cloud / policy / checks 정보를 추가했다.
v3 PR 2: REVIEW(검토 필요) 판정을 추가했다.
  - 값이 변수·표현식이라 안전한지 확인할 수 없으면 PASS가 아니라 REVIEW
  - REVIEW도 배포를 막는다 (종료 코드 1)
  - 파일 판정 우선순위: ERROR > BLOCK > REVIEW > PASS
"""

import argparse
import json
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# 규칙 메타데이터
#   - cloud  : 이 규칙이 속한 클라우드 (aws / azure / gcp)
#   - policy : 공통 보안 정책 ID. 클라우드 고유 정책은 None
#   - verdict: 이 규칙에 걸렸을 때의 판정 (BLOCK = 위반 확인, REVIEW = 판단 불가)
# 새 규칙을 추가할 때는 이 표에도 한 줄을 추가한다.
# ---------------------------------------------------------------------------

POLICY_NAMES = {
    "CG-NET-01": "관리자 포트 인터넷 공개 금지",
    "CG-STO-01": "저장소 공개 금지",
}

RULES = {
    "AWS_PUBLIC_ADMIN_PORT":     {"cloud": "aws",   "policy": "CG-NET-01", "verdict": "BLOCK"},
    "AWS_ADMIN_PORT_UNRESOLVED": {"cloud": "aws",   "policy": "CG-NET-01", "verdict": "REVIEW"},
    "AWS_S3_PUBLIC_BLOCK_OFF":   {"cloud": "aws",   "policy": "CG-STO-01", "verdict": "BLOCK"},
    "AWS_S3_BLOCK_UNRESOLVED":    {"cloud": "aws",   "policy": "CG-STO-01", "verdict": "REVIEW"},
    "AWS_S3_WILDCARD_PRINCIPAL": {"cloud": "aws",   "policy": "CG-STO-01", "verdict": "BLOCK"},
    "AWS_S3_POLICY_UNRESOLVED":   {"cloud": "aws",   "policy": "CG-STO-01", "verdict": "REVIEW"},
    "AWS_S3_NO_PUBLIC_BLOCK":    {"cloud": "aws",   "policy": "CG-STO-01", "verdict": "REVIEW"},
    "AZURE_HARDCODED_PASSWORD":  {"cloud": "azure", "policy": None,        "verdict": "BLOCK"},
    "AZURE_WIDE_FIREWALL":       {"cloud": "azure", "policy": None,        "verdict": "BLOCK"},
    "AZURE_OLD_TLS":             {"cloud": "azure", "policy": None,        "verdict": "BLOCK"},
    "GCP_PROJECT_OWNER":         {"cloud": "gcp",   "policy": None,        "verdict": "BLOCK"},
    "GCP_SERVICE_ACCOUNT_KEY":   {"cloud": "gcp",   "policy": None,        "verdict": "BLOCK"},
}

# 공통 정책별로 "현재 검사기가 실제로 검사하는" 자원 종류.
# 여기 있는 자원은 위반이 없어도 checks 목록에 PASS로 기록된다.
# (Azure·GCP 자원은 PR 3~6에서 규칙과 함께 추가한다.)
POLICY_TARGETS = {
    ("CG-NET-01", "aws"): {"aws_security_group", "aws_vpc_security_group_ingress_rule"},
    ("CG-STO-01", "aws"): {"aws_s3_bucket", "aws_s3_bucket_public_access_block", "aws_s3_bucket_policy"},
}

# 판정의 "나쁜 정도". 숫자가 클수록 나쁘다. 여러 결과가 있으면 가장 나쁜 것을 따른다.
SEVERITY = {"PASS": 0, "REVIEW": 1, "BLOCK": 2, "ERROR": 3}


def worst(statuses, default="PASS"):
    statuses = list(statuses)
    return max(statuses, key=SEVERITY.get) if statuses else default


def file_status(findings):
    """위반 목록으로 파일 판정을 정한다: BLOCK > REVIEW > PASS (ERROR는 읽기 실패 시)."""
    return worst(f["verdict"] for f in findings)


def cloud_of(resource_type):
    """자원 종류 이름의 앞부분으로 클라우드를 구분한다."""
    if resource_type.startswith("aws_"):
        return "aws"
    if resource_type.startswith("azurerm_"):
        return "azure"
    if resource_type.startswith("google_"):
        return "gcp"
    return "other"


# ---------------------------------------------------------------------------
# 값 읽기 도우미
# python-hcl2는 var.x, local.y, 다른 자원 참조 같은 표현식을 "${...}" 문자열로 준다.
# 이런 값은 실제 값을 알 수 없으므로 "확인 불가(None)"로 다룬다.
# ---------------------------------------------------------------------------

def blocks(value):
    """HCL block values are commonly lists of dictionaries."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def resources(data):
    """Yield (type, name, body) from a python-hcl2 resource structure."""
    for outer in blocks(data.get("resource", [])):
        for resource_type, named in outer.items():
            if str(resource_type).startswith("__"):
                continue
            for name, body in named.items() if isinstance(named, dict) else []:
                if isinstance(body, dict):
                    yield resource_type, name, body


def string_value(value):
    """Strip optional quote wrappers from HCL parser text values."""
    return str(value).strip().strip('"\'')


def is_unresolved(value):
    """변수·표현식이라 실제 값을 알 수 없으면 True."""
    if isinstance(value, list):
        return any(is_unresolved(v) for v in value)
    if isinstance(value, dict):
        return any(is_unresolved(v) for v in value.values())
    return isinstance(value, str) and "${" in value


def public_cidr(value):
    """True = 인터넷 전체 / False = 아님 / None = 확인 불가."""
    if value is None:
        return False
    items = value if isinstance(value, list) else [value]
    if any(not is_unresolved(v) and string_value(v) in ("0.0.0.0/0", "::/0") for v in items):
        return True
    if any(is_unresolved(v) for v in items):
        return None
    return False


def any_public(*values):
    """여러 출발지 칸 중 하나라도 공개면 True, 아니면 확인 불가가 있으면 None."""
    results = [public_cidr(v) for v in values]
    if True in results:
        return True
    if None in results:
        return None
    return False


def covers_admin_ports(body):
    """True = 22/3389(또는 전체 포트) 포함 / False = 아님 / None = 확인 불가."""
    raw_proto = body.get("protocol", body.get("ip_protocol", "tcp"))
    if is_unresolved(raw_proto):
        return None
    proto = string_value(raw_proto).lower()
    if proto in ("-1", "all"):
        return True
    from_port, to_port = body.get("from_port"), body.get("to_port")
    if is_unresolved(from_port) or is_unresolved(to_port):
        return None
    if from_port is None or to_port is None:
        return False
    try:
        start, end = int(from_port), int(to_port)
    except (TypeError, ValueError):
        return None  # 숫자가 아닌 값 → 판단 불가
    return any(start <= port <= end for port in (22, 3389))


def is_literal_secret(value):
    if not isinstance(value, str) or not value.strip():
        return False
    val = string_value(value).strip()
    # Do not flag references to a Terraform variable or secret store as literals.
    return not (val.startswith("${") or val.startswith("var.") or
                val.startswith("data.") or val.startswith("local.") or
                val.startswith("random_password."))


# ---------------------------------------------------------------------------
# S3 버킷 ↔ 공개 차단 설정 연결
# 공개 차단 설정(aws_s3_bucket_public_access_block)의 bucket 값이
#   - 버킷 이름과 같거나 (bucket = "my-bucket")
#   - 버킷 자원을 참조하면 (bucket = aws_s3_bucket.logs.id)
# 연결된 것으로 본다. 검사하는 파일 전체(폴더)를 대상으로 찾는다.
# ---------------------------------------------------------------------------

def collect_s3_links(datas):
    names, refs = set(), set()
    for data in datas:
        for typ, _name, body in resources(data):
            if typ != "aws_s3_bucket_public_access_block":
                continue
            target = body.get("bucket")
            if target is None:
                continue
            refs.update(re.findall(r"aws_s3_bucket\.([A-Za-z0-9_-]+)", str(target)))
            if not is_unresolved(target):
                names.add(string_value(target))
    return {"names": names, "refs": refs}


def bucket_has_public_block(name, body, links):
    if name in links["refs"]:
        return True
    bucket = body.get("bucket")
    return bucket is not None and not is_unresolved(bucket) and string_value(bucket) in links["names"]


# ---------------------------------------------------------------------------
# S3 정책/공개 차단 판정 도우미 (PR 2의 미완성 규칙 보완)
# 정적 분석 가능한 JSON 정책과 리터럴 Boolean만 안전하다고 판정한다.
# ---------------------------------------------------------------------------

S3_PUBLIC_BLOCK_FLAGS = (
    "block_public_acls", "block_public_policy",
    "ignore_public_acls", "restrict_public_buckets",
)


def s3_flag_state(value):
    """True/False = 명확한 Boolean, None = 변수·생략·알 수 없는 값."""
    if value is True or (isinstance(value, str) and value.strip().lower() == "true"):
        return True
    if value is False or (isinstance(value, str) and value.strip().lower() == "false"):
        return False
    return None


def wildcard_principal(principal):
    """AWS 정책 JSON의 Principal 문자열/객체/리스트 중 *가 있는지 검사."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(wildcard_principal(v) for v in principal.values())
    if isinstance(principal, list):
        return any(wildcard_principal(v) for v in principal)
    return False


def evaluate_s3_policy(raw):
    """Return ('BLOCK'|'PASS'|'REVIEW', explanation).

    S3 정책 JSON의 Statement(복수 또는 단일)를 확인한다.
    * Effect=Allow + Principal=* 일 때만 명확히 위반 (BLOCK)
    * Effect=Deny + Principal=* 는 공개 허용이 아니므로 PASS
    * jsonencode()/변수/JSON 파싱 실패는 REVIEW (정책 안전성 불명)
    """
    if raw is None or (isinstance(raw, str) and raw.strip().startswith("${")):
        return "REVIEW", "S3 정책을 읽을 수 없음(생략·변수·표현식, jsonencode 포함)"
    try:
        doc = raw if isinstance(raw, dict) else json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        return "REVIEW", "S3 정책을 JSON 문서로 해석할 수 없음"
    if not isinstance(doc, dict):
        return "REVIEW", "S3 정책 JSON의 최상위 구조가 객체가 아님"
    statements = doc.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        return "REVIEW", "S3 정책에 해석 가능한 Statement가 없음"
    uncertain = False
    for statement in statements:
        if not isinstance(statement, dict):
            uncertain = True
            continue
        effect = statement.get("Effect")
        principal = statement.get("Principal")
        if not isinstance(effect, str) or is_unresolved(effect):
            uncertain = True
            continue
        if effect.lower() == "deny":
            continue  # 공개 대상 전체에 Deny를 쓰는 것은 공개 허용이 아니다.
        if effect.lower() != "allow":
            uncertain = True
            continue
        if principal is None or is_unresolved(principal):
            uncertain = True
            continue
        if wildcard_principal(principal):
            return "BLOCK", "S3 정책에서 Effect=Allow이면서 Principal=*로 공개 접근을 허용하는 설정"
        if not isinstance(principal, (str, dict, list)):
            uncertain = True
    if uncertain:
        return "REVIEW", "S3 정책 일부를 해석할 수 없어 공개 허용 여부 확인이 필요함"
    return "PASS", "명시적으로 전체 사용자에게 Allow하는 정책을 찾지 못함"


# ---------------------------------------------------------------------------
# 검사 규칙
# ---------------------------------------------------------------------------

def scan_configuration(data, s3_links=None):
    """Return rule violations (BLOCK) and undecidable items (REVIEW) for a parsed HCL document."""
    if s3_links is None:
        s3_links = collect_s3_links([data])
    findings = []

    def add(rule, resource, reason):
        meta = RULES[rule]
        findings.append({"rule": rule, "resource": resource, "reason": reason,
                         "cloud": meta["cloud"], "policy": meta["policy"],
                         "verdict": meta["verdict"]})

    def check_admin_port(ref, body, *cidr_values):
        public = any_public(*cidr_values)
        admin = covers_admin_ports(body)
        if public is False or admin is False:
            return  # 공개가 아니거나 관리자 포트가 아니면 문제 없음
        if public and admin:
            add("AWS_PUBLIC_ADMIN_PORT", ref,
                "인터넷 전체에 SSH(22), RDP(3389) 또는 전체 포트 범위 노출")
        else:
            add("AWS_ADMIN_PORT_UNRESOLVED", ref,
                "출발지·포트·프로토콜 중 변수·표현식 값이 있어 관리자 포트 공개 여부를 확인할 수 없음 (검토 필요)")

    for typ, name, body in resources(data):
        ref = f"{typ}.{name}"

        # AWS S3 bucket without any linked public-access block.
        if typ == "aws_s3_bucket" and not bucket_has_public_block(name, body, s3_links):
            add("AWS_S3_NO_PUBLIC_BLOCK", ref,
                "S3 버킷에 연결된 공개 차단 설정(aws_s3_bucket_public_access_block)이 없어 공개 여부를 확인할 수 없음 (검토 필요)")

        # AWS S3 공개 접근 차단: false면 BLOCK, 판단 불가/생략이면 REVIEW.
        # 하나라도 false가 확실하면 다른 옵션이 변수여도 BLOCK이 우선한다.
        if typ == "aws_s3_bucket_public_access_block":
            states = {flag: s3_flag_state(body.get(flag)) for flag in S3_PUBLIC_BLOCK_FLAGS}
            off = [flag for flag, state in states.items() if state is False]
            unknown = [flag for flag, state in states.items() if state is None]
            if off:
                add("AWS_S3_PUBLIC_BLOCK_OFF", ref,
                    "S3 공개 접근 차단 옵션 비활성화: " + ", ".join(off))
            elif unknown:
                add("AWS_S3_BLOCK_UNRESOLVED", ref,
                    "S3 공개 접근 차단 옵션 값을 확인할 수 없음(변수·표현식·생략): " + ", ".join(unknown))

        # AWS S3 bucket policy: Principal=*라도 Deny면 공개 허용이 아니다.
        if typ == "aws_s3_bucket_policy":
            verdict, reason = evaluate_s3_policy(body.get("policy"))
            if verdict == "BLOCK":
                add("AWS_S3_WILDCARD_PRINCIPAL", ref, reason)
            elif verdict == "REVIEW":
                add("AWS_S3_POLICY_UNRESOLVED", ref, reason)

        # AWS security group allows public SSH/RDP or all ports.
        if typ == "aws_security_group":
            for ingress in blocks(body.get("ingress", [])):
                check_admin_port(ref, ingress,
                                 ingress.get("cidr_blocks"), ingress.get("ipv6_cidr_blocks"))
        if typ == "aws_vpc_security_group_ingress_rule":
            check_admin_port(ref, body, body.get("cidr_ipv4"), body.get("cidr_ipv6"))

        # Azure DB server passwords written as literal Terraform strings.
        if typ.startswith("azurerm_"):
            for password_key in ("administrator_login_password", "administrator_password"):
                if password_key in body and is_literal_secret(body[password_key]):
                    add("AZURE_HARDCODED_PASSWORD", ref,
                        "관리자 비밀번호가 설정 파일에 직접 기록됨 (실제 값은 출력하지 않음)")
                    break
            if (string_value(body.get("start_ip_address", "")) == "0.0.0.0" and
                string_value(body.get("end_ip_address", "")) == "255.255.255.255"):
                add("AZURE_WIDE_FIREWALL", ref,
                    "DB 방화벽이 전체 IPv4 범위를 허용함")
            if string_value(body.get("minimum_tls_version", "")) in ("1.0", "1.1"):
                add("AZURE_OLD_TLS", ref, "오래된 TLS 최소 버전(1.0 또는 1.1) 허용")

        # Google Cloud project-wide owner role.
        if typ in ("google_project_iam_member", "google_project_iam_binding"):
            if string_value(body.get("role", "")) == "roles/owner":
                add("GCP_PROJECT_OWNER", ref,
                    "계정에 프로젝트 전체 관리자(Owner) 권한을 부여함")
        if typ == "google_service_account_key":
            add("GCP_SERVICE_ACCOUNT_KEY", ref,
                "서비스 계정 장기 키 생성: 프로젝트 정책상 차단 (데모 기준)")

    return findings


def build_checks(data, findings):
    """공통 정책의 검사 대상 자원마다 "검사했음" 기록을 만든다.

    상태는 그 자원·정책에 걸린 결과 중 가장 나쁜 것 (없으면 PASS).
    이 기록이 있어야 나중에 "검사 대상 없음(N/A)"과 "검사했고 문제 없음(PASS)"을 구분할 수 있다.
    """
    checks = []
    for typ, name, _body in resources(data):
        ref = f"{typ}.{name}"
        cloud = cloud_of(typ)
        for (policy, target_cloud), target_types in POLICY_TARGETS.items():
            if cloud == target_cloud and typ in target_types:
                status = worst(f["verdict"] for f in findings
                               if f["resource"] == ref and f["policy"] == policy)
                checks.append({"resource": ref, "cloud": cloud,
                               "policy": policy, "status": status})
    return checks


def load_tf(path):
    import hcl2  # Installation: py -m pip install -r requirements.txt
    with path.open("r", encoding="utf-8") as f:
        return hcl2.load(f)


def scan_file(path):
    """파일 1개의 위반·검토 목록 (self_test.py도 이 함수를 사용한다).

    파일 하나만 보고 판단하므로, S3 버킷과 공개 차단 설정은 같은 파일 안에서만 연결을 찾는다.
    """
    return scan_configuration(load_tf(path))


def main():
    parser = argparse.ArgumentParser(description="교육용 Terraform 보안 정책 게이트")
    parser.add_argument("folder", type=Path, help="검사할 .tf 파일 또는 폴더")
    parser.add_argument("--json", type=Path, help="검사 결과를 저장할 JSON 파일")
    args = parser.parse_args()

    if not args.folder.exists():
        print(f"[ERROR] 경로가 없습니다: {args.folder}")
        return 2
    tf_files = sorted(args.folder.rglob("*.tf")) if args.folder.is_dir() else [args.folder]
    if not tf_files or any(path.suffix != ".tf" for path in tf_files):
        print("[ERROR] 검사할 .tf 파일이 없습니다.")
        return 2

    try:
        import hcl2  # noqa: F401
    except ImportError:
        print("[ERROR] python-hcl2 설치 필요: py -m pip install -r requirements.txt")
        return 2

    # 1단계: 모든 파일을 먼저 읽는다 (S3 버킷과 공개 차단 설정이 다른 파일에 있을 수 있음)
    parsed, errors = {}, {}
    for path in tf_files:
        try:
            parsed[path] = load_tf(path)
        except Exception as exc:
            errors[path] = f"{type(exc).__name__}: {exc}"  # Fail closed: never a PASS.
    s3_links = collect_s3_links(parsed.values())

    # 2단계: 파일별로 검사한다
    results = []
    for path in tf_files:
        if path in errors:
            findings, checks, status, error = [], [], "ERROR", errors[path]
        else:
            findings = scan_configuration(parsed[path], s3_links)
            checks = build_checks(parsed[path], findings)
            status, error = file_status(findings), None
        results.append({"file": str(path), "status": status,
                        "findings": findings, "checks": checks, "error": error})
        print(f"[{status}] {path}")
        for finding in findings:
            tag = finding["cloud"] + (f"/{finding['policy']}" if finding["policy"] else "")
            print(f"   - {finding['verdict']} {finding['rule']} [{tag}]: {finding['reason']}")
        if error:
            print(f"   - 분석 오류: {error}")

    counts = {status: sum(r["status"] == status for r in results)
              for status in ("PASS", "REVIEW", "BLOCK", "ERROR")}
    print(f"\n총 {len(results)}개  |  PASS {counts['PASS']}  |  REVIEW {counts['REVIEW']}  "
          f"|  BLOCK {counts['BLOCK']}  |  ERROR {counts['ERROR']}")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"JSON 저장: {args.json}")
    if counts["ERROR"]:
        return 2
    return 1 if (counts["BLOCK"] or counts["REVIEW"]) else 0


if __name__ == "__main__":
    sys.exit(main())
