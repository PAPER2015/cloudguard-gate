"""Educational Terraform policy gate (AWS/Azure/GCP).

Usage:
  py -m pip install -r requirements.txt     (python-hcl2==7.3.1)
  py policy_gate.py infra --json results.json

This is a *starter* static checker. PASS means only these selected demo rules
passed, not that a Terraform configuration is production secure.

v3 PR 1: 결과에 cloud / policy / checks 정보를 추가했다. 판정(PASS/BLOCK)은 v2와 같다.
"""

import argparse
import json
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# 규칙 메타데이터 (v3)
#   - cloud : 이 규칙이 속한 클라우드 (aws / azure / gcp)
#   - policy: 공통 보안 정책 ID. 공통 정책에 속하지 않는 "클라우드 고유 정책"은 None
# 새 규칙을 추가할 때는 이 표에도 한 줄을 추가한다.
# ---------------------------------------------------------------------------

POLICY_NAMES = {
    "CG-NET-01": "관리자 포트 인터넷 공개 금지",
    "CG-STO-01": "저장소 공개 금지",
}

RULES = {
    "AWS_PUBLIC_ADMIN_PORT":     {"cloud": "aws",   "policy": "CG-NET-01"},
    "AWS_S3_PUBLIC_BLOCK_OFF":   {"cloud": "aws",   "policy": "CG-STO-01"},
    "AWS_S3_WILDCARD_PRINCIPAL": {"cloud": "aws",   "policy": "CG-STO-01"},
    "AZURE_HARDCODED_PASSWORD":  {"cloud": "azure", "policy": None},
    "AZURE_WIDE_FIREWALL":       {"cloud": "azure", "policy": None},
    "AZURE_OLD_TLS":             {"cloud": "azure", "policy": None},
    "GCP_PROJECT_OWNER":         {"cloud": "gcp",   "policy": None},
    "GCP_SERVICE_ACCOUNT_KEY":   {"cloud": "gcp",   "policy": None},
}

# 공통 정책별로 "현재 검사기가 실제로 검사하는" 자원 종류.
# 여기 있는 자원은 위반이 없어도 checks 목록에 PASS로 기록된다.
# (Azure·GCP 자원은 PR 3~6에서 규칙과 함께 추가한다.)
POLICY_TARGETS = {
    ("CG-NET-01", "aws"): {"aws_security_group", "aws_vpc_security_group_ingress_rule"},
    ("CG-STO-01", "aws"): {"aws_s3_bucket_public_access_block", "aws_s3_bucket_policy"},
}


def cloud_of(resource_type):
    """자원 종류 이름의 앞부분으로 클라우드를 구분한다."""
    if resource_type.startswith("aws_"):
        return "aws"
    if resource_type.startswith("azurerm_"):
        return "azure"
    if resource_type.startswith("google_"):
        return "gcp"
    return "other"


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


def public_cidr(value):
    if isinstance(value, list):
        return any(public_cidr(v) for v in value)
    return string_value(value) in ("0.0.0.0/0", "::/0")


def covers_admin_ports(body):
    proto = string_value(body.get("protocol", body.get("ip_protocol", "tcp"))).lower()
    if proto in ("-1", "all"):
        return True
    try:
        start = int(body.get("from_port"))
        end = int(body.get("to_port"))
    except (TypeError, ValueError):
        return False
    return any(start <= port <= end for port in (22, 3389))


def is_literal_secret(value):
    if not isinstance(value, str) or not value.strip():
        return False
    val = string_value(value).strip()
    # Do not flag references to a Terraform variable or secret store as literals.
    return not (val.startswith("${") or val.startswith("var.") or
                val.startswith("data.") or val.startswith("local.") or
                val.startswith("random_password."))


def scan_configuration(data):
    """Return rule violations for a parsed HCL document."""
    findings = []

    def add(rule, resource, reason):
        meta = RULES[rule]
        findings.append({"rule": rule, "resource": resource, "reason": reason,
                         "cloud": meta["cloud"], "policy": meta["policy"]})

    for typ, name, body in resources(data):
        ref = f"{typ}.{name}"

        # AWS S3 public-access controls disabled.
        if typ == "aws_s3_bucket_public_access_block":
            flags = ("block_public_acls", "block_public_policy",
                     "ignore_public_acls", "restrict_public_buckets")
            off = [flag for flag in flags if body.get(flag) is False or
                   string_value(body.get(flag, "")).lower() == "false"]
            if off:
                add("AWS_S3_PUBLIC_BLOCK_OFF", ref,
                    "S3 공개 접근 차단 옵션 비활성화: " + ", ".join(off))

        # AWS S3 policy explicitly permits wildcard Principal.
        if typ == "aws_s3_bucket_policy":
            policy = str(body.get("policy", ""))
            if re.search(r'(?:["\']?Principal["\']?\s*[:=]\s*["\']?\*|'
                         r'["\']AWS["\']\s*[:=]\s*["\']?\*)', policy, flags=re.I):
                add("AWS_S3_WILDCARD_PRINCIPAL", ref,
                    "S3 정책에서 모든 사용자(*)에게 접근을 허용할 가능성")

        # AWS security group allows public SSH/RDP or all ports.
        if typ == "aws_security_group":
            for ingress in blocks(body.get("ingress", [])):
                if (public_cidr(ingress.get("cidr_blocks", [])) or
                    public_cidr(ingress.get("ipv6_cidr_blocks", []))) and covers_admin_ports(ingress):
                    add("AWS_PUBLIC_ADMIN_PORT", ref,
                        "인터넷 전체에 SSH(22), RDP(3389) 또는 전체 포트 범위 노출")
        if typ == "aws_vpc_security_group_ingress_rule":
            if (public_cidr(body.get("cidr_ipv4", "")) or
                public_cidr(body.get("cidr_ipv6", ""))) and covers_admin_ports(body):
                add("AWS_PUBLIC_ADMIN_PORT", ref,
                    "인터넷 전체에 SSH(22), RDP(3389) 또는 전체 포트 범위 노출")

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

    위반이 있으면 BLOCK, 없으면 PASS. 이 기록이 있어야 나중에
    "검사 대상 없음(N/A)"과 "검사했고 문제 없음(PASS)"을 구분할 수 있다.
    """
    blocked = {(f["resource"], f["policy"]) for f in findings if f["policy"]}
    checks = []
    for typ, name, _body in resources(data):
        ref = f"{typ}.{name}"
        cloud = cloud_of(typ)
        for (policy, target_cloud), target_types in POLICY_TARGETS.items():
            if cloud == target_cloud and typ in target_types:
                status = "BLOCK" if (ref, policy) in blocked else "PASS"
                checks.append({"resource": ref, "cloud": cloud,
                               "policy": policy, "status": status})
    return checks


def load_tf(path):
    import hcl2  # Installation: py -m pip install -r requirements.txt
    with path.open("r", encoding="utf-8") as f:
        return hcl2.load(f)


def scan_file(path):
    """파일 1개의 위반 목록 (self_test.py도 이 함수를 사용한다)."""
    return scan_configuration(load_tf(path))


def scan_file_detail(path):
    """파일 1개의 (위반 목록, 검사 기록)."""
    data = load_tf(path)
    findings = scan_configuration(data)
    return findings, build_checks(data, findings)


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
        print("[ERROR] python-hcl2 설치 필요: py -m pip install python-hcl2")
        return 2

    results = []
    for path in tf_files:
        try:
            findings, checks = scan_file_detail(path)
            status = "BLOCK" if findings else "PASS"
            error = None
        except Exception as exc:
            findings, checks = [], []
            status = "ERROR"  # Fail closed: parse errors must never be a PASS.
            error = f"{type(exc).__name__}: {exc}"
        results.append({"file": str(path), "status": status,
                        "findings": findings, "checks": checks, "error": error})
        print(f"[{status}] {path}")
        for finding in findings:
            tag = finding["cloud"] + (f"/{finding['policy']}" if finding["policy"] else "")
            print(f"   - {finding['rule']} [{tag}]: {finding['reason']}")
        if error:
            print(f"   - 분석 오류: {error}")

    counts = {status: sum(r["status"] == status for r in results)
              for status in ("PASS", "BLOCK", "ERROR")}
    print(f"\n총 {len(results)}개  |  PASS {counts['PASS']}  "
          f"|  BLOCK {counts['BLOCK']}  |  ERROR {counts['ERROR']}")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"JSON 저장: {args.json}")
    return 2 if counts["ERROR"] else (1 if counts["BLOCK"] else 0)


if __name__ == "__main__":
    sys.exit(main())
