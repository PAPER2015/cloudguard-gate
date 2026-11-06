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
v3 PR 3: 공통 정책 CG-NET-01(관리자 포트 인터넷 공개 금지)을 Azure NSG에도 적용했다.
  - azurerm_network_security_rule, azurerm_network_security_group 내부 security_rule
v3 PR 4: CG-NET-01을 GCP 방화벽(google_compute_firewall)에도 적용했다. → AWS·Azure·GCP 세 클라우드 공통
v3 PR 4 보완: 3종 GCP 방화벽 정책 규칙의 단순 설정 검사 및 복잡한 설정 REVIEW 처리.
v3 PR 5: 공통 정책 CG-STO-01(저장소 공개 금지)을 Azure Storage로 확장했다.
  - 판정은 정책 위반 기준, 실제 노출 가능성은 exposure 항목으로 따로 기록 (정적 구성 기준)
  - azurerm 버전별 기본값: 잠금 파일 > required_providers 제약 (Terraform 평가 방식과 동일)
  - 폴더 검사 부분을 scan_paths()로 분리 (동작 동일)
  - AZURE_OLD_TLS: 저장소의 min_tls_version = "TLS1_0"/"TLS1_1" 도 탐지 (조용한 PASS 수정)
v3 PR 5 최종(GPT 추가 교차 검토 반영):
  - azapi blobServices 의 properties.staticWebsite.enabled 도 정적 웹사이트로 검토
  - 연결 템플릿(templateLink)은 내용을 볼 수 없으므로 REVIEW
  - TLS: azapi minimumTlsVersion 도 검사, TLS 값이 변수·표현식이면 AZURE_TLS_UNRESOLVED(REVIEW)
  - 버전 제약 계산을 표본 대신 정확한 구간 계산으로 교체 (큰 버전 숫자, 사전 공개 버전)
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
    "AZURE_PUBLIC_ADMIN_PORT":   {"cloud": "azure", "policy": "CG-NET-01", "verdict": "BLOCK"},
    "AZURE_ADMIN_PORT_UNRESOLVED": {"cloud": "azure", "policy": "CG-NET-01", "verdict": "REVIEW"},
    "AZURE_HARDCODED_PASSWORD":  {"cloud": "azure", "policy": None,        "verdict": "BLOCK"},
    "AZURE_WIDE_FIREWALL":       {"cloud": "azure", "policy": None,        "verdict": "BLOCK"},
    "AZURE_OLD_TLS":             {"cloud": "azure", "policy": None,        "verdict": "BLOCK"},
    "AZURE_TLS_UNRESOLVED":      {"cloud": "azure", "policy": None,        "verdict": "REVIEW"},
    "AZURE_STORAGE_PUBLIC_ALLOWED":    {"cloud": "azure", "policy": "CG-STO-01", "verdict": "BLOCK"},
    "AZURE_STORAGE_CONTAINER_PUBLIC":  {"cloud": "azure", "policy": "CG-STO-01", "verdict": "BLOCK"},
    "AZURE_STORAGE_PUBLIC_UNRESOLVED": {"cloud": "azure", "policy": "CG-STO-01", "verdict": "REVIEW"},
    "AZURE_STORAGE_STATIC_WEBSITE":    {"cloud": "azure", "policy": "CG-STO-01", "verdict": "REVIEW"},
    "AZURE_STORAGE_UNSUPPORTED":       {"cloud": "azure", "policy": "CG-STO-01", "verdict": "REVIEW"},
    "GCP_STORAGE_PUBLIC_IAM":          {"cloud": "gcp", "policy": "CG-STO-01", "verdict": "BLOCK"},
    "GCP_STORAGE_PUBLIC_ACL":          {"cloud": "gcp", "policy": "CG-STO-01", "verdict": "BLOCK"},
    "GCP_STORAGE_PAP_NOT_ENFORCED":    {"cloud": "gcp", "policy": "CG-STO-01", "verdict": "REVIEW"},
    "GCP_STORAGE_PUBLIC_UNRESOLVED":   {"cloud": "gcp", "policy": "CG-STO-01", "verdict": "REVIEW"},
    "GCP_STORAGE_UNSUPPORTED":         {"cloud": "gcp", "policy": "CG-STO-01", "verdict": "REVIEW"},
    "GCP_PUBLIC_ADMIN_PORT":     {"cloud": "gcp",   "policy": "CG-NET-01", "verdict": "BLOCK"},
    "GCP_ADMIN_PORT_UNRESOLVED": {"cloud": "gcp",   "policy": "CG-NET-01", "verdict": "REVIEW"},
    "GCP_FIREWALL_POLICY_PUBLIC_ADMIN_PORT": {"cloud": "gcp", "policy": "CG-NET-01", "verdict": "BLOCK"},
    "GCP_FIREWALL_POLICY_UNRESOLVED": {"cloud": "gcp", "policy": "CG-NET-01", "verdict": "REVIEW"},
    "GCP_PROJECT_OWNER":         {"cloud": "gcp",   "policy": None,        "verdict": "BLOCK"},
    "GCP_SERVICE_ACCOUNT_KEY":   {"cloud": "gcp",   "policy": None,        "verdict": "BLOCK"},
}

# 공통 정책별로 "현재 검사기가 실제로 검사하는" 자원 종류.
# 여기 있는 자원은 위반이 없어도 checks 목록에 PASS로 기록된다.
# (GCP 저장소는 v3 PR 6에서 추가: 버킷 + IAM 6종 + ACL 6종.
#  Azure 저장소는 자원 종류만으로 대상을 정할 수 없는 azapi·템플릿 배포가 있어
#  build_checks 에서 is_azure_storage_check_target() 로 따로 판단한다.)
POLICY_TARGETS = {
    ("CG-NET-01", "aws"): {"aws_security_group", "aws_vpc_security_group_ingress_rule"},
    ("CG-NET-01", "azure"): {"azurerm_network_security_rule", "azurerm_network_security_group"},
    ("CG-NET-01", "gcp"): {
        "google_compute_firewall",
        "google_compute_firewall_policy_rule",
        "google_compute_network_firewall_policy_rule",
        "google_compute_region_network_firewall_policy_rule",
    },
    ("CG-STO-01", "aws"): {"aws_s3_bucket", "aws_s3_bucket_public_access_block", "aws_s3_bucket_policy"},
    ("CG-STO-01", "gcp"): {
        "google_storage_bucket",
        "google_storage_bucket_iam_member", "google_storage_bucket_iam_binding",
        "google_storage_bucket_iam_policy",
        "google_storage_managed_folder_iam_member", "google_storage_managed_folder_iam_binding",
        "google_storage_managed_folder_iam_policy",
        "google_storage_bucket_acl", "google_storage_object_acl", "google_storage_default_object_acl",
        "google_storage_bucket_access_control", "google_storage_object_access_control",
        "google_storage_default_object_access_control",
    },
}

# 정책 × 클라우드 지원 범위 (v3 PR 6). Summary 의 행렬이 이 표와 checks 기록으로 만들어진다.
# 자원 목록은 policy_support_resources() 가 POLICY_TARGETS·Azure 판단과 같은 출처에서 계산한다
# (표와 실제 검사 대상이 어긋나지 않게 — tests/test_summary_matrix.py 가 확인).
POLICY_SUPPORT = {
    ("CG-NET-01", "aws"): "보안 그룹 인라인·별도 규칙만. 접두사 목록·NACL·WAF 는 보지 않음",
    ("CG-NET-01", "azure"): "NSG 규칙만. Azure Firewall·서비스 태그 세부 범위는 보지 않음",
    ("CG-NET-01", "gcp"): "VPC 방화벽·방화벽 정책 규칙 3종. *_with_rules 등 다른 규칙 형식·주소 그룹은 REVIEW",
    ("CG-STO-01", "aws"): "버킷·공개 차단·버킷 정책. 계정 수준 공개 차단·ACL 자원은 보지 않음",
    ("CG-STO-01", "azure"): "계정·컨테이너·정적 웹사이트·azapi. ARM 템플릿 안의 값은 REVIEW, 환경 변수 영향 미반영",
    ("CG-STO-01", "gcp"): "버킷 PAP·IAM·ACL·Managed Folder. 조직 정책 실효값 미확인(inherited 는 REVIEW)",
}
POLICY_CLOUDS = ("aws", "azure", "gcp")

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
    if resource_type.startswith("azurerm_") or resource_type.startswith("azapi_"):
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
# Azure NSG 규칙 판정 도우미 (v3 PR 3, CG-NET-01)
# 조건 5개를 각각 예(True) / 아니오(False) / 모름(None)으로 본다.
#   - 하나라도 아니오 → 안전 (PASS)
#   - 모두 예        → 위반 (BLOCK)
#   - 그 외          → 판단 불가 (REVIEW)
# Azure 값(Inbound, Allow, Tcp, Internet)은 대소문자를 구분하지 않는다.
# ---------------------------------------------------------------------------

AZURE_PUBLIC_SOURCES = {"*", "internet", "0.0.0.0/0", "::/0"}
ADMIN_PORTS = (22, 3389)


def text_state(value, yes, no):
    """문자열 값이 yes 목록이면 True, no 목록이면 False, 그 외(생략·변수·처음 보는 값)는 None."""
    if value is None or is_unresolved(value):
        return None
    text = string_value(value).lower()
    if text in yes:
        return True
    if text in no:
        return False
    return None


def as_items(value):
    """한 개 값이든 목록이든 목록으로 바꾼다. 생략(None)이면 빈 목록."""
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def azure_source_public(rule):
    """출발지가 인터넷 전체인가? (source_address_prefix / source_address_prefixes)"""
    values = as_items(rule.get("source_address_prefix")) + as_items(rule.get("source_address_prefixes"))
    if not values:
        # 출발지 주소 대신 특정 VM 그룹(ASG)만 지정했다면 인터넷 전체가 아니다.
        return False if rule.get("source_application_security_group_ids") else None
    if any(not is_unresolved(v) and string_value(v).lower() in AZURE_PUBLIC_SOURCES for v in values):
        return True
    if any(is_unresolved(v) for v in values):
        return None
    return False


def port_spec_covers_admin(spec):
    """Azure 포트 표기 1개가 22/3389를 포함하는가? "22", "20-30", "*", 22(숫자)."""
    if isinstance(spec, bool) or spec is None or is_unresolved(spec):
        return None
    if isinstance(spec, int):
        return spec in ADMIN_PORTS if 0 <= spec <= 65535 else None
    text = string_value(spec).strip()
    if text == "*":
        return True
    match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", text)
    if match:
        start, end = int(match.group(1)), int(match.group(2))
        if not (0 <= start <= end <= 65535):
            return None  # 잘못된 범위(예: 30-20, 70000) → 판단 불가
        return any(start <= port <= end for port in ADMIN_PORTS)
    if text.isdigit():
        port = int(text)
        return port in ADMIN_PORTS if port <= 65535 else None
    return None  # 처음 보는 표기 → 판단 불가


def azure_ports_cover_admin(rule):
    """목적지 포트가 관리자 포트를 포함하는가? (destination_port_range / destination_port_ranges)"""
    values = as_items(rule.get("destination_port_range")) + as_items(rule.get("destination_port_ranges"))
    if not values:
        return None
    results = [port_spec_covers_admin(v) for v in values]
    if True in results:
        return True
    if None in results:
        return None
    return False


def evaluate_azure_rule(rule):
    """NSG 규칙 1개 → ('BLOCK'|'REVIEW'|'PASS', 확인 못 한 항목 목록)."""
    conditions = {
        "direction": text_state(rule.get("direction"), {"inbound"}, {"outbound"}),
        "access": text_state(rule.get("access"), {"allow"}, {"deny"}),
        "protocol": text_state(rule.get("protocol"), {"tcp", "*"}, {"udp", "icmp", "esp", "ah"}),
        "출발지": azure_source_public(rule),
        "목적지 포트": azure_ports_cover_admin(rule),
    }
    if False in conditions.values():
        return "PASS", []
    unknown = [name for name, state in conditions.items() if state is None]
    return ("REVIEW", unknown) if unknown else ("BLOCK", [])


# ---------------------------------------------------------------------------
# GCP 방화벽 판정 도우미 (v3 PR 4, CG-NET-01)
# google_compute_firewall 하나를 조건 4개로 본다: 예(True) / 아니오(False) / 모름(None)
#   - 하나라도 아니오 → 안전 (PASS)
#   - 모두 예        → 위반 (BLOCK)
#   - 그 외          → 판단 불가 (REVIEW)
# Terraform google provider 문서 기준:
#   - direction 생략 시 INGRESS
#   - INGRESS는 source_ranges / source_tags / source_service_accounts 중 하나가 필요
#   - source_ranges와 source_tags를 함께 쓰면 "둘 중 하나라도 맞으면" 적용 (OR)
#   - allow의 ports를 생략하면 그 프로토콜의 모든 포트
# ---------------------------------------------------------------------------

GCP_PUBLIC_RANGES = {"0.0.0.0/0", "::/0"}
GCP_TCP_PROTOCOLS = {"tcp", "6"}   # 6 = TCP의 IP 프로토콜 번호


def is_opaque_block_list(value):
    """블록 목록 자체가 변수·표현식이라 안을 볼 수 없는가? (블록 안의 개별 변수는 해당 없음)"""
    return value is not None and (
        not isinstance(value, (list, dict))
        or (isinstance(value, list) and any(not isinstance(item, dict) for item in value)))


def gcp_direction_ingress(body):
    direction = body.get("direction")
    if direction is None:
        return True   # 생략 시 기본값 INGRESS
    return text_state(direction, {"ingress"}, {"egress"})


def gcp_rule_enabled(body):
    disabled = body.get("disabled")
    if disabled is None or disabled is False:
        return True
    if disabled is True:
        return False  # 비활성 규칙은 트래픽에 적용되지 않음
    return text_state(disabled, {"false"}, {"true"})  # "true"/"false" 문자열, 변수는 None


def gcp_source_public(body):
    """출발지가 인터넷 전체인가?

    - source_ranges에 0.0.0.0/0 또는 ::/0가 있으면 예 (source_tags가 같이 있어도 OR 이므로 예)
    - source_ranges가 특정 대역뿐이면 아니오
    - source_ranges 없이 source_tags / source_service_accounts만 있으면 아니오
      (특정 VM에서 오는 트래픽만 해당)
    - 출발지를 하나도 지정하지 않았으면 모름 (provider 버전에 따라 오류이거나 GCP 기본값 0.0.0.0/0)
    """
    ranges = body.get("source_ranges")
    if ranges is not None and not isinstance(ranges, list):
        return None if is_unresolved(ranges) else (
            True if string_value(ranges) in GCP_PUBLIC_RANGES else False)
    items = ranges or []
    if any(not is_unresolved(r) and string_value(r) in GCP_PUBLIC_RANGES for r in items):
        return True
    if any(is_unresolved(r) for r in items):
        return None
    if items:
        return False
    instance_sources = [body.get("source_tags"), body.get("source_service_accounts")]
    if any(v is not None and v != [] for v in instance_sources):
        return False
    return None


def gcp_allow_covers_admin(allow):
    """allow 블록 하나가 TCP 22/3389를 허용하는가?"""
    protocol = allow.get("protocol")
    if protocol is None or is_unresolved(protocol):
        return None
    protocol = string_value(protocol).lower()
    if protocol == "all":
        return True
    if protocol not in GCP_TCP_PROTOCOLS:
        return False  # udp, icmp 등은 SSH/RDP(TCP) 접속이 아님
    ports = allow.get("ports")
    if ports is None or ports == []:
        return True   # ports 생략 = 모든 TCP 포트
    if not isinstance(ports, list):
        return None if is_unresolved(ports) else port_spec_covers_admin(ports)
    results = [port_spec_covers_admin(p) for p in ports]
    if True in results:
        return True
    if None in results:
        return None
    return False


def gcp_allows_admin(body):
    """방화벽의 allow 블록 전체 중 관리자 포트를 허용하는 것이 있는가? (deny 블록은 허용이 아님)"""
    allows = body.get("allow")
    results = []
    if is_opaque_block_list(allows):
        results.append(None)              # allow = var.rules 처럼 목록 전체가 변수
    else:
        results.extend(gcp_allow_covers_admin(a) for a in blocks(allows))
    if any("allow" in dyn for dyn in blocks(body.get("dynamic", []))):
        results.append(None)              # dynamic "allow" 블록은 해석하지 않음
    if True in results:
        return True
    if None in results:
        return None
    return False                          # allow가 없거나(deny만) 모두 안전


def evaluate_gcp_firewall(body):
    """GCP 방화벽 1개 → ('BLOCK'|'REVIEW'|'PASS', 확인 못 한 항목 목록)."""
    conditions = {
        "direction": gcp_direction_ingress(body),
        "disabled": gcp_rule_enabled(body),
        "출발지": gcp_source_public(body),
        "허용 포트": gcp_allows_admin(body),
    }
    if False in conditions.values():
        return "PASS", []
    unknown = [name for name, state in conditions.items() if state is None]
    return ("REVIEW", unknown) if unknown else ("BLOCK", [])



# ---------------------------------------------------------------------------
# GCP 방화벽 정책 규칙 (PR 4 보완)
# 공식 Terraform 유형: 계층형 / 전역 네트워크 / 리전 네트워크 Firewall Policy Rule.
# 기존 google_compute_firewall과 구조가 달라 별도로 판정한다.
# 단순한 action/direction/match/src_ip_ranges/layer4_configs는 분석하며,
# 평가할 수 없는 source selector, dynamic block, expression은 REVIEW로 차단한다.
# 주의: Terraform 정적 분석으로 실제 우선순위/연결/실제 유효 트래픽을 확증하지 않는다.
# ---------------------------------------------------------------------------

GCP_FIREWALL_POLICY_RULE_TYPES = {
    "google_compute_firewall_policy_rule",
    "google_compute_network_firewall_policy_rule",
    "google_compute_region_network_firewall_policy_rule",
}


def is_other_gcp_firewall_policy_rule_type(resource_type):
    """아직 이름을 등록하지 않은 GCP Firewall Policy Rule 계열의 안전한 기본 처리.

    *_firewall_policy_with_rules 자원(정책 안에 rule 블록을 직접 넣는 방식)도 포함한다.
    이 자원들은 아직 내용을 해석하지 않으므로, 결과에서 빠지지 않도록 REVIEW로 차단한다.
    """
    return (resource_type.startswith("google_compute_")
            and ("firewall_policy_rule" in resource_type
                 or "firewall_policy_with_rules" in resource_type)
            and resource_type not in GCP_FIREWALL_POLICY_RULE_TYPES)


def gcp_policy_public_source(match):
    """공개 출발지? 단순한 src_ip_ranges만 확정하고 다른 selector는 보수적으로 REVIEW."""
    ranges = match.get("src_ip_ranges")
    if ranges is not None and not isinstance(ranges, list):
        return None
    items = ranges or []
    # 정책 리소스의 복잡한 소스 조건은 OR/AND 관계를 안전하게 평가할 수 없다.
    # 공개 주소가 함께 나타나도 다른 source selector가 있으면 BLOCK으로 단정하지 않는다.
    other_selectors = (
        "src_address_groups", "src_secure_tags", "src_fqdns", "src_region_codes",
        "src_threat_intelligences", "src_networks", "src_network_scope",
    )
    if any(match.get(k) not in (None, [], "") for k in other_selectors):
        return None
    if any("src_secure_tags" in dyn for dyn in blocks(match.get("dynamic", []))):
        return None
    if any(not is_unresolved(v) and isinstance(v, str)
           and string_value(v) in GCP_PUBLIC_RANGES for v in items):
        return True
    if any(is_unresolved(v) or not isinstance(v, str) for v in items):
        return None
    if items:
        return False
    return None  # 생략·빈 목록에 기본값을 가정하지 않음


def gcp_policy_admin_ports(match):
    """match.layer4_configs의 TCP 22/3389 포함 여부 (다중 블록 포함)."""
    configs = match.get("layer4_configs")
    if is_opaque_block_list(configs):
        return None
    results = [gcp_allow_covers_admin({"protocol": c.get("ip_protocol"),
                                       "ports": c.get("ports")})
               for c in blocks(configs)]
    if any("layer4_configs" in dyn for dyn in blocks(match.get("dynamic", []))):
        results.append(None)
    if True in results:
        return True
    if None in results or not results:
        return None
    return False


def evaluate_gcp_firewall_policy_rule(body):
    """3종 GCP 방화벽 정책 규칙의 단순/확실한 위험을 구분하는 보수적 판정."""
    direction = body.get("direction")
    conditions = {
        "direction": (text_state(direction, {"ingress"}, {"egress"})
                      if direction is not None else None),
        "disabled": gcp_rule_enabled(body),
        # apply_security_profile_group: 트래픽을 검사 장비로 보낸 뒤 통과시킨다
        # (검사 실패 시 기본 동작도 allow) → 허용과 같이 본다.
        "action": (text_state(body.get("action"), {"allow", "apply_security_profile_group"},
                              {"deny", "goto_next"})
                   if body.get("action") is not None else None),
    }
    if False in conditions.values():
        return "PASS", []  # 비활성/EGRESS/deny 등은 이 규칙으로 관리자 인바운드 허용 불가

    match_value = body.get("match")
    matches = blocks(match_value)
    if (is_opaque_block_list(match_value) or len(matches) != 1 or
            any("match" in dyn for dyn in blocks(body.get("dynamic", [])))):
        conditions["match"] = None
    else:
        match = matches[0]
        conditions["출발지"] = gcp_policy_public_source(match)
        conditions["허용 포트"] = gcp_policy_admin_ports(match)

    if False in conditions.values():
        return "PASS", []
    unknown = [key for key, value in conditions.items() if value is None]
    return ("REVIEW", unknown) if unknown else ("BLOCK", [])



# ---------------------------------------------------------------------------
# Terraform provider 버전 제약 해석 (v3 PR 5)
# Terraform이 provider 제약을 평가할 때 쓰는 라이브러리(apparentlymart/go-versions v1.0.2,
# constraints.ParseRubyStyleMulti + versions.MeetingConstraints)와 같은 결과를 내도록 만들었다.
# tests/fixtures/terraform_version_constraints.json 에 그 라이브러리로 직접 계산한 정답이 있고,
# tests/test_terraform_version.py 가 이 함수와 비교한다. (만드는 방법: tools/terraform_version_oracle/)
# ---------------------------------------------------------------------------

_TF_VERSION = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?$")
_TF_CONDITION = re.compile(r"^(~>|>=|<=|!=|=|>|<)? ?(.+)$")   # 연산자 뒤 공백은 0개 또는 1개만 (라이브러리 규칙)
TF_CANDIDATE_MAJORS = range(1, 8)   # 1~7. 알려진 AzureRM 메이저는 1~5, 6 이상은 "미래"
# 이 라이브러리의 규칙 (go-versions v1.0.2 소스와 실제 실행으로 확인):
#  - 빠진 자리는 0으로 채운다. "= 4" 는 4.0.0 하나, "<= 4" 는 4.0.0 이하 (4.x 전체가 아님)
#  - "~> 4", "~> 4.1" 은 다음 메이저 전까지, "~> 4.1.2" 는 다음 부 버전 전까지
#  - 사전 공개 버전(4.0.0-beta1)은 "= 4.0.0-beta1" 처럼 정확히 지목했을 때만 후보가 된다


def _tf_parse_version(text):
    match = _TF_VERSION.match(text)
    if not match:
        return None
    nums = [int(g) for g in match.groups()[:3] if g is not None]
    return nums, match.group(4)


def parse_version_constraints(text):
    """'~> 4.0, != 4.52.0' → 조건 목록 [(연산자, 숫자들, 사전공개표시)]. 문법 오류는 None."""
    conditions = []
    if not text.strip():
        return conditions
    for piece in text.split(","):
        piece = piece.strip()
        match = _TF_CONDITION.match(piece)
        if not piece or not match:
            return None
        op, version = match.group(1) or "=", match.group(2)
        parsed = _tf_parse_version(version)
        if parsed is None:
            return None
        conditions.append((op, parsed[0], parsed[1]))
    return conditions


def _tf_conditions(texts):
    conditions = []
    for text in texts:
        parsed = parse_version_constraints(text)
        if parsed is None:
            return None
        conditions.extend(parsed)
    return conditions


def _tf_zero(nums):
    """빠진 자리를 0으로 채운 (주, 부, 수) 세 숫자."""
    return tuple(nums + [0] * (3 - len(nums)))


def _tf_pre_less(a, b):
    """사전 공개 표시 비교. 라이브러리 VersionExtra.LessThan 을 그대로 옮겼다 (점 개수 우선 등 특이점 포함)."""
    if a == b:
        return False
    while True:
        d1, d2 = a.find("."), b.find(".")
        if d1 == -1 and d2 != -1:
            return True
        if d2 == -1 and d1 != -1:
            return False
        if d1 == -1:
            return _tf_ident_less(a, b)
        if a[:d1] != b[:d2]:
            return _tf_ident_less(a[:d1], b[:d2])
        a, b = a[d1 + 1:], b[d2 + 1:]


def _tf_ident_less(a, b):
    a_num, b_num = a.isdigit(), b.isdigit()
    if a_num != b_num:
        return a_num                      # 숫자로만 된 쪽이 앞
    if a_num:
        return (len(a), a) < (len(b), b)
    return a < b


def _tf_less(v, w):
    """v < w. 버전은 ((주, 부, 수), 사전공개표시 또는 None)."""
    if v[0] != w[0]:
        return v[0] < w[0]
    if v[1] == w[1]:
        return False
    if v[1] is None:
        return False                      # 정식 버전이 같은 숫자의 사전 공개보다 뒤
    if w[1] is None:
        return True
    return _tf_pre_less(v[1], w[1])


def _tf_upper(op, nums):
    """'~>' 의 상한 (이 값 미만). 숫자를 3개 적으면 다음 부 버전, 아니면 다음 메이저."""
    if len(nums) == 3:
        return (nums[0], nums[1] + 1, 0)
    return (nums[0] + 1, 0, 0)


def _tf_exact_has(version, condition):
    """라이브러리 MeetingConstraintsExact 와 같은 조건 판정 (사전 공개 버전 포함)."""
    op, nums, pre = condition
    bound = (_tf_zero(nums), pre)
    same = version == bound
    if op == "=":
        return same
    if op == "!=":
        return not same
    if op == ">":
        return _tf_less(bound, version)
    if op == ">=":
        return same or _tf_less(bound, version)
    if op == "<":
        return _tf_less(version, bound)
    if op == "<=":
        return same or _tf_less(version, bound)
    if op == "~>":
        return (same or _tf_less(bound, version)) and _tf_less(version, (_tf_upper(op, nums), None))
    return False


def _tf_has(version, conditions):
    """라이브러리 MeetingConstraints.Has: 정식 버전은 모든 조건을 만족하면 포함.
    사전 공개 버전은 '=' 로 정확히 지목되었고 모든 조건을 만족할 때만 포함."""
    if not all(_tf_exact_has(version, c) for c in conditions):
        return False
    if version[1] is None:
        return True
    return any(op == "=" and (_tf_zero(nums), pre) == version for op, nums, pre in conditions)


def _tf_release_range(condition):
    """정식 버전만 볼 때 조건 하나가 허용하는 구간 [하한, 상한)과 빼야 할 점.
    세 숫자는 사전식 순서이고, (a, b, c) 바로 다음 정식 버전은 (a, b, c + 1) 이다."""
    op, nums, pre = condition
    z = _tf_zero(nums)
    nxt = (z[0], z[1], z[2] + 1)
    if op == "=":
        return (None, None, None) if pre else (z, nxt, None)     # 사전 공개 지정이면 정식 버전 없음
    if op == "!=":
        return (None, "inf", None if pre else z)
    if op == ">":
        return (z if pre else nxt, "inf", None)                 # 4.0.0 > 4.0.0-beta 이므로 pre면 z부터
    if op == ">=":
        return (z, "inf", None)
    if op == "<":
        return (None, z, None)
    if op == "<=":
        return (None, z if pre else nxt, None)                  # 4.0.0 은 4.0.0-beta 보다 크므로 제외
    if op == "~>":
        return (z, _tf_upper(op, nums), None)
    return (None, None, None)


def _tf_release_exists(low, high, excluded):
    """[low, high) 안에 excluded 에 없는 정식 버전이 하나라도 있는가 (high 는 미포함)."""
    if not low < high:
        return False
    if low[:2] != high[:2]:
        return True                      # 수 버전이 끝없이 이어지므로 유한 개를 빼도 남는다
    count = high[2] - low[2]             # 같은 (주, 부) 안: 정확히 count 개
    inside = {p for p in excluded if low <= p < high}
    return count > len(inside)


def possible_major_versions(texts):
    """제약 문자열들(모두 만족해야 함)을 만족하는 버전이 있는 메이저 집합. 문법 오류면 None.
    표본을 찍어 보는 대신 구간을 직접 계산하므로 4.121.0, 4.0.121 같은 큰 숫자도 정확하다."""
    conditions = _tf_conditions(texts)
    if conditions is None:
        return None
    majors = set()
    for major in TF_CANDIDATE_MAJORS:
        low, high, excluded, empty = (major, 0, 0), (major + 1, 0, 0), set(), False
        for condition in conditions:
            c_low, c_high, c_point = _tf_release_range(condition)
            if c_high is None:
                empty = True
                break
            if c_low is not None:
                low = max(low, c_low)
            if c_high != "inf":
                high = min(high, c_high)
            if c_point is not None:
                excluded.add(c_point)
        if not empty and _tf_release_exists(low, high, excluded):
            majors.add(major)
    for op, nums, pre in conditions:                       # 정확히 지목된 사전 공개 버전
        if op == "=" and pre and nums[0] in TF_CANDIDATE_MAJORS:
            if _tf_has((_tf_zero(nums), pre), conditions):
                majors.add(nums[0])
    return majors


def version_satisfies(version_text, texts):
    """정확한 버전(잠금 파일)이 제약들을 모두 만족하는가. 해석 불가면 None."""
    parsed = _tf_parse_version(version_text.strip())
    conditions = _tf_conditions(texts)
    if parsed is None or conditions is None:
        return None
    nums, pre = parsed
    return _tf_has((_tf_zero(nums), pre), conditions)


# ---------------------------------------------------------------------------
# Azure Storage 공개 위험 (v3 PR 5, CG-STO-01)
# 정책: 저장소 데이터를 인증 없이 읽을 수 있게 하거나, 그것을 가능하게 하는 계정 수준 보호
#       장치를 끄는 설정을 금지한다. (판정 = 정책 위반 / exposure = 정적 구성 기준 노출 상태)
# exposure 값 (모두 Terraform 정적 구성 기준이며, 실제 클라우드 접근을 확인한 것이 아니다)
#   anonymous_access_configured : 계정 허용 + 공개 컨테이너가 확인된 참조로 함께 구성됨
#   public_access_possible      : 공개가 가능한 상태지만 짝이 되는 설정을 확인하지 못함
#   blocked_by_account_setting  : 컨테이너는 공개 선언, 연결된 계정이 익명 접근을 막음
#   intentional_static_website  : 정적 웹사이트 ($web 은 계정 설정과 무관하게 공개)
#   undetermined                : 값을 확인할 수 없음
# ---------------------------------------------------------------------------

AZURERM_PROVIDER_ADDRESSES = {"hashicorp/azurerm", "registry.terraform.io/hashicorp/azurerm"}
# 메이저별 "익명 접근 허용" 필드 생략 시 기본값. None = 정적으로 알 수 없음
#   v1: 필드 없음(Azure 서비스 기본값) / v2: allow_blob_public_access=false
#   v3·v4: allow_nested_items_to_be_public=true (v4는 ARM_FIVEPOINTZERO_BETA=true 이면 false)
#   v5: false / v6 이상: 아직 없음
AZURERM_PUBLIC_DEFAULT = {1: None, 2: False, 3: True, 4: True, 5: False}

STORAGE_ACCOUNT = "azurerm_storage_account"
STORAGE_CONTAINER = "azurerm_storage_container"
STORAGE_STATIC_WEBSITE = "azurerm_storage_account_static_website"
STORAGE_NETWORK_RULES = "azurerm_storage_account_network_rules"
AZAPI_TYPES = {"azapi_resource", "azapi_update_resource"}
TEMPLATE_DEPLOYMENT_TYPES = {
    "azurerm_resource_group_template_deployment", "azurerm_subscription_template_deployment",
    "azurerm_management_group_template_deployment", "azurerm_tenant_template_deployment",
}
ARM_STORAGE_ACCOUNT = "microsoft.storage/storageaccounts"
ARM_STORAGE_CONTAINER = "microsoft.storage/storageaccounts/blobservices/containers"
ARM_BLOB_SERVICE = "microsoft.storage/storageaccounts/blobservices"   # staticWebsite 설정이 여기 있다
ARM_DEPLOYMENT = "microsoft.resources/deployments"
_ACCOUNT_REF = re.compile(r"^\$\{azurerm_storage_account\.([A-Za-z0-9_-]+)(?:\[[^\]]*\])?\.(?:id|name)\}$")
_FILE_CALL = re.compile(r'^\$\{file\("(?:\$\{path\.module\}/)?([^"$]+)"\)\}$')
_JSONENCODE = re.compile(r"^\$\{jsonencode\((.*)\)\}$", re.S)
_DYNAMIC_REF = re.compile(r"\b(var|local|module|data|each|count|path|terraform)\.|templatefile\(|file\(")
EXPOSURE_NOTE = " (Terraform 정적 구성 기준이며 실제 클라우드 접근을 확인한 것은 아님)"


def bool_state(value):
    """True / False / None(생략·변수·처음 보는 값)."""
    if isinstance(value, bool):
        return value
    if value is None or is_unresolved(value):
        return None
    return {"true": True, "false": False}.get(string_value(value).lower())


def azurerm_constraints(data):
    """required_providers 의 azurerm 버전 제약 목록과, 다른 출처(source)를 쓰는지 여부."""
    constraints, foreign = [], False
    for block in blocks(data.get("terraform", [])):
        for providers in blocks(block.get("required_providers", [])):
            spec = providers.get("azurerm")
            if spec is None:
                continue
            if isinstance(spec, str):                       # 옛 문법: azurerm = "~> 4.0"
                constraints.append(string_value(spec))
                continue
            if isinstance(spec, dict):
                source = spec.get("source")
                if source is not None and string_value(source).lower() not in AZURERM_PROVIDER_ADDRESSES:
                    foreign = True
                version = spec.get("version")
                if version is not None:
                    if is_unresolved(version):
                        foreign = True                      # 변수 제약 → 해석 불가로 처리
                    else:
                        constraints.append(string_value(version))
    for block in blocks(data.get("provider", [])):           # 옛 문법: provider "azurerm" { version = ... }
        spec = block.get("azurerm")
        if isinstance(spec, dict) and spec.get("version") is not None:
            constraints.append(string_value(spec["version"]))
    return constraints, foreign


def lock_file_azurerm_version(lock_path):
    """.terraform.lock.hcl 에 고정된 azurerm 버전 (없거나 읽을 수 없으면 None)."""
    if not lock_path.is_file():
        return None
    try:
        import hcl2
        with lock_path.open("r", encoding="utf-8") as f:
            data = hcl2.load(f)
    except Exception:
        return "unreadable"
    for block in blocks(data.get("provider", [])):
        for address, body in block.items():
            if string_value(address).lower() in AZURERM_PROVIDER_ADDRESSES and isinstance(body, dict):
                version = body.get("version")
                return string_value(version) if version is not None else "unreadable"
    return None


def public_default_from_majors(majors):
    """가능한 메이저들의 기본값이 모두 같을 때만 그 값. 아니면 None."""
    if not majors:
        return None
    values = {AZURERM_PUBLIC_DEFAULT.get(m) for m in majors}
    return values.pop() if len(values) == 1 else None


def module_calls(data, module_dir):
    """로컬 경로(./, ../)로 부르는 하위 모듈 폴더 목록."""
    called = []
    for block in blocks(data.get("module", [])):
        for _name, body in block.items():
            source = body.get("source") if isinstance(body, dict) else None
            if source is None or is_unresolved(source):
                continue
            source = string_value(source)
            if source.startswith("./") or source.startswith("../"):
                called.append((module_dir / source).resolve())
    return called


def resolve_version_contexts(parsed_by_dir, lock_reader=lock_file_azurerm_version):
    """폴더(모듈)마다 azurerm 버전 판단 결과를 만든다.

    Terraform 규칙: 잠금 파일은 루트 모듈에만 있고, 루트와 그 하위 모듈의 provider 제약은
    모두 동시에 만족해야 한다. 여기서는 로컬 경로 module 호출로 루트·하위 관계를 찾는다.
    반환: {폴더: {"default": True/False/None, "note": 판단 근거 문장}}
    """
    dirs = {d.resolve(): d for d in parsed_by_dir}
    info = {}
    for key, original in dirs.items():
        cons, foreign = [], False
        children = []
        for data in parsed_by_dir[original]:
            c, f = azurerm_constraints(data)
            cons.extend(c)
            foreign = foreign or f
            children.extend(m for m in module_calls(data, key) if m in dirs and m != key)
        info[key] = {"constraints": cons, "foreign": foreign, "children": children}
    called = {child for meta in info.values() for child in meta["children"]}
    roots = [d for d in info if d not in called]

    def tree(root):
        seen, stack = [], [root]
        while stack:
            d = stack.pop()
            if d in seen:
                continue
            seen.append(d)
            stack.extend(info[d]["children"])
        return seen

    results = {}
    for root in roots:
        members = tree(root)
        cons = [c for d in members for c in info[d]["constraints"]]
        foreign = any(info[d]["foreign"] for d in members)
        lock = lock_reader(root / ".terraform.lock.hcl")
        if foreign:
            outcome = (None, "azurerm 출처나 버전 제약이 표준 형태가 아님")
        elif lock == "unreadable":
            outcome = (None, "잠금 파일을 해석할 수 없음")
        elif lock:
            ok = version_satisfies(lock, cons)
            parsed = _tf_parse_version(lock)
            if ok is not True or parsed is None:
                outcome = (None, f"잠금 파일 버전 {lock}이 제약과 맞지 않거나 해석 불가")
            else:
                outcome = (public_default_from_majors({parsed[0][0]}), f"잠금 파일 azurerm {lock}")
        elif cons:
            majors = possible_major_versions(cons)
            if majors is None:
                outcome = (None, "버전 제약 문법 오류")
            else:
                shown = ", ".join(f"v{m}" for m in sorted(majors)) or "없음"
                outcome = (public_default_from_majors(majors),
                           f"버전 제약 {' + '.join(cons)} → 가능한 메이저 {shown}")
        else:
            outcome = (None, "azurerm 버전 정보 없음")
        for d in members:
            results.setdefault(d, []).append(outcome)

    contexts = {}
    for key, original in dirs.items():
        outcomes = results.get(key) or [(None, "루트 모듈을 찾을 수 없음 (순환 호출 등)")]
        values = {o[0] for o in outcomes}
        default = values.pop() if len(values) == 1 else None
        contexts[original] = {"default": default, "note": "; ".join(o[1] for o in outcomes)}
    return contexts


def account_network_state(body, rule_bodies):
    """'public' / 'restricted' / 'unknown' — 판정에는 쓰지 않고 사유 문구에만 쓴다."""
    states = []
    enabled = body.get("public_network_access_enabled")
    if enabled is not None:
        states.append({True: "public", False: "restricted"}.get(bool_state(enabled), "unknown"))
    access = body.get("public_network_access")
    if access is not None:
        text = None if is_unresolved(access) else string_value(access).lower()
        states.append("public" if text == "enabled" else "unknown" if text is None else "restricted")
    for rules in blocks(body.get("network_rules")) + rule_bodies:
        action = rules.get("default_action")
        text = None if action is None or is_unresolved(action) else string_value(action).lower()
        states.append({"allow": "public", "deny": "restricted"}.get(text, "unknown"))
    if "restricted" in states:
        return "restricted"
    if "unknown" in states:
        return "unknown"
    return "public"


NETWORK_LABEL = {"public": "공개", "restricted": "제한됨", "unknown": "확인 불가"}


def evaluate_storage_account(body, public_default, version_note):
    """계정 하나 → (판정, 사유, 실효 공개 허용 True/False/None)."""
    kind = body.get("account_kind")
    file_only = (kind is not None and not is_unresolved(kind)
                 and string_value(kind).lower() == "filestorage")
    values = [body[k] for k in ("allow_nested_items_to_be_public", "allow_blob_public_access") if k in body]
    states = [bool_state(v) for v in values]
    if True in states:
        return "BLOCK", "계정이 컨테이너 익명 공개를 허용함 (명시 설정)", True
    if file_only:
        return "PASS", "FileStorage 계정은 Blob 서비스가 없어 익명 Blob 접근이 불가능", False
    if states and all(s is False for s in states):
        return "PASS", "", False
    if states:
        return "REVIEW", "익명 공개 허용 값이 변수·표현식이라 확인할 수 없음", None
    if public_default is True:
        return "BLOCK", f"익명 공개 허용 설정 생략 → 기본값 true ({version_note})", True
    if public_default is False:
        return "PASS", "", False
    return "REVIEW", f"익명 공개 허용 설정 생략, 기본값을 정할 수 없음 ({version_note})", None


def container_access_state(value):
    """'public' / 'private' / None(확인 불가)."""
    if value is None:
        return "private"                                     # 기본값 private
    if is_unresolved(value):
        return None
    text = string_value(value).lower()
    if text in ("blob", "container"):
        return "public"
    return "private" if text in ("private", "none") else None


def build_storage_index(datas):
    """같은 폴더(모듈) 안의 Storage 계정 색인: 자원 이름 → 정보, 리터럴 name → 자원 이름들."""
    accounts, by_name, rule_bodies, container_links = {}, {}, {}, {}
    for data in datas:
        for typ, name, body in resources(data):
            if typ == STORAGE_ACCOUNT:
                accounts[name] = body
                literal = body.get("name")
                if literal is not None and not is_unresolved(literal):
                    by_name.setdefault(string_value(literal), []).append(name)
    index = {"accounts": accounts, "by_name": by_name}
    for data in datas:
        for typ, name, body in resources(data):
            target = link_storage_account(body, index)
            if typ == STORAGE_NETWORK_RULES and target:
                rule_bodies.setdefault(target, []).append(body)
            if typ == STORAGE_CONTAINER and target:
                container_links.setdefault(target, []).append(container_access_state(body.get("container_access_type")))
    index["network_rules"] = rule_bodies
    index["container_states"] = container_links
    return index


def link_storage_account(body, index):
    """컨테이너 등이 가리키는 같은 폴더의 계정 자원 이름. 확실하지 않으면 None."""
    for key in ("storage_account_id", "storage_account_name"):
        value = body.get(key)
        if value is None:
            continue
        text = str(value)
        match = _ACCOUNT_REF.match(text)
        if match:
            return match.group(1) if match.group(1) in index["accounts"] else None
        if is_unresolved(value):
            return None                                       # 변수·data·module → 연결하지 않음
        literal = string_value(value)
        if key == "storage_account_id":
            literal = literal.rstrip("/").split("/")[-1] if "/storageaccounts/" in literal.lower() else ""
        candidates = index["by_name"].get(literal, [])
        return candidates[0] if len(candidates) == 1 else None   # 이름이 유일할 때만
    return None


def azapi_type_base(body):
    """azapi 자원의 type → '@버전' 앞부분 소문자. 확인 불가면 None."""
    value = body.get("type")
    if value is None or is_unresolved(value):
        return None
    return string_value(value).split("@")[0].strip().lower()


def azapi_body(body):
    """azapi body → dict. jsonencode(리터럴)이면 풀어서 dict. 해석 불가면 None."""
    value = body.get("body")
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        match = _JSONENCODE.match(value.strip())
        if match and "${" not in match.group(1):
            try:
                decoded = json.loads(match.group(1))
                return decoded if isinstance(decoded, dict) else None
            except ValueError:
                return None
    return None


def template_text_state(text_value, module_dir):
    """ARM 템플릿 내용 → 'storage' / 'linked' / 'clear' / 'unknown'.
    'linked': templateLink(uri·relativePath·id)로 바깥 템플릿을 불러와 내용을 볼 수 없음."""
    if text_value is None:
        return "clear"
    if isinstance(text_value, (dict, list)):
        text = json.dumps(text_value)
    else:
        text = str(text_value)
        match = _FILE_CALL.match(text.strip())
        if match:
            path = (module_dir / match.group(1)) if module_dir else None
            if path is None or not path.is_file():
                return "unknown"
            text = path.read_text(encoding="utf-8", errors="replace")
    if ARM_STORAGE_ACCOUNT in text.lower():
        return "storage"
    if "templatelink" in text.lower():                   # ARM 속성 이름은 대소문자 구분 없음
        return "linked"
    if "${" in text and _DYNAMIC_REF.search(text):
        return "unknown"
    return "clear"


def is_azure_storage_check_target(typ, body):
    """CG-STO-01(Azure) checks 에 기록할 자원인가."""
    if typ in (STORAGE_ACCOUNT, STORAGE_CONTAINER, STORAGE_STATIC_WEBSITE) or typ in TEMPLATE_DEPLOYMENT_TYPES:
        return True
    if typ in AZAPI_TYPES:
        base = azapi_type_base(body)
        return base is None or base in (ARM_STORAGE_ACCOUNT, ARM_STORAGE_CONTAINER, ARM_BLOB_SERVICE,
                                        ARM_DEPLOYMENT)
    return False


def make_azure_context(datas, version_context=None, module_dir=None):
    """scan_configuration 에 넘길 Azure Storage 판단 재료 (같은 폴더 기준)."""
    if version_context is None:
        version_context = resolve_version_contexts({Path("."): list(datas)}, lock_reader=lambda _p: None)[Path(".")]
    return {"index": build_storage_index(datas), "default": version_context["default"],
            "note": version_context["note"], "module_dir": module_dir}



# ---------------------------------------------------------------------------
# GCP Cloud Storage 공개 위험 (CG-STO-01 → GCP, v3 PR 6)
# 정책: 공개 주체(allUsers·allAuthenticatedUsers)에게 버킷·폴더·객체 권한을 부여하는 선언 자체를 금지.
#   - 공개 주체가 확정이면 역할과 무관하게 BLOCK (역할이 불명이면 exposure = undetermined)
#   - 버킷의 공개 접근 방지(PAP)가 enforced 가 아니면 REVIEW (조직 정책에 달려 확인 불가)
#   - 버킷 연결은 exposure 에만 쓰고 판정을 완화하지 않는다
# 근거: docs.cloud.google.com/storage/docs/public-access-prevention, .../uniform-bucket-level-access,
#       .../access-control/lists, Terraform google provider storage_bucket_iam·storage_bucket_acl 문서
# ---------------------------------------------------------------------------

GCP_BUCKET = "google_storage_bucket"
GCP_IAM_TYPES = {
    "google_storage_bucket_iam_member", "google_storage_bucket_iam_binding", "google_storage_bucket_iam_policy",
    "google_storage_managed_folder_iam_member", "google_storage_managed_folder_iam_binding",
    "google_storage_managed_folder_iam_policy",
}
GCP_ACL_LIST_TYPES = {"google_storage_bucket_acl", "google_storage_object_acl", "google_storage_default_object_acl"}
GCP_ACL_ENTITY_TYPES = {"google_storage_bucket_access_control", "google_storage_object_access_control",
                        "google_storage_default_object_access_control"}
# CG-STO-01 범위 밖으로 분류한 google_storage_* 자원 (권한을 부여하지 않음). 판정·checks 없음.
# 검사 대상(POLICY_TARGETS) + 이 목록이 provider 의 storage 자원 전체를 덮는지 tests/test_resource_catalog.py 가 확인한다.
GCP_STORAGE_OUT_OF_SCOPE = {
    "google_storage_bucket_object",           # 객체 업로드 (ACL 인수 없음, 기본 객체 ACL 을 따름)
    "google_storage_managed_folder",          # 폴더 자체는 권한 없음 (IAM 은 *_iam_* 에서 검사)
    "google_storage_folder",                  # 계층형 네임스페이스 폴더
    "google_storage_notification", "google_storage_hmac_key", "google_storage_transfer_job",
    "google_storage_transfer_agent_pool", "google_storage_anywhere_cache", "google_storage_batch_operations_job",
    "google_storage_insights_dataset_config", "google_storage_insights_report_config",
    "google_storage_control_folder_intelligence_config", "google_storage_control_organization_intelligence_config",
    "google_storage_control_project_intelligence_config", "google_storage_control_project_feature_config",
    "google_storage_ftp_server", "google_storage_ftp_user",   # SFTP: 인증 사용자용, 익명 공개 경로 아님 (한계에 기록)
}
GCP_PUBLIC_MEMBERS = {"allusers": "allUsers", "allauthenticatedusers": "allAuthenticatedUsers",
                      "principalset://goog/public:all": "allUsers"}
GCP_MEMBER_PREFIXES = ("user:", "serviceaccount:", "group:", "domain:", "projectowner:", "projecteditor:",
                       "projectviewer:", "principal://", "principalset://", "deleted:")
GCP_ACL_ENTITY_PREFIXES = ("user-", "group-", "domain-", "project-")
GCP_PUBLIC_PREDEFINED = {"publicread": ("allUsers", "읽기"), "publicreadwrite": ("allUsers", "읽기·쓰기"),
                         "authenticatedread": ("allAuthenticatedUsers", "읽기")}
GCP_ROLE_LEVEL = {
    "roles/storage.objectviewer": "읽기", "roles/storage.legacyobjectreader": "읽기",
    "roles/storage.legacybucketreader": "읽기(목록)",
    "roles/storage.objectcreator": "쓰기", "roles/storage.objectuser": "읽기·쓰기",
    "roles/storage.legacybucketwriter": "쓰기",
    "roles/storage.objectadmin": "관리", "roles/storage.admin": "관리",
    "roles/storage.legacybucketowner": "관리", "roles/storage.legacyobjectowner": "관리",
}
GCP_ACL_ROLE_LEVEL = {"reader": "읽기", "writer": "쓰기", "owner": "관리"}
_GCP_BUCKET_REF = re.compile(r"^\$\{google_storage_bucket\.([A-Za-z0-9_-]+)(?:\[[^\]]*\])?\.(?:name|id|url|self_link)\}$")
_GCP_POLICY_DATA_REF = re.compile(r"^\$\{data\.google_iam_policy\.([A-Za-z0-9_-]+)\.policy_data\}$")


def data_sources(data):
    """(type, name, body) for data blocks (resources() 는 resource 블록만 본다)."""
    for outer in blocks(data.get("data", [])):
        for data_type, named in outer.items():
            for name, body in named.items() if isinstance(named, dict) else []:
                if isinstance(body, dict):
                    yield data_type, name, body


def gcp_member_state(value):
    """IAM 구성원 하나 → 'allUsers' / 'allAuthenticatedUsers' / False(공개 아님) / None(확인 불가) / 'unknown'(처음 보는 형식)."""
    if value is None or is_unresolved(value) or isinstance(value, (list, dict)):
        return None
    text = string_value(value).strip()
    lower = text.lower()
    if lower in GCP_PUBLIC_MEMBERS:
        return GCP_PUBLIC_MEMBERS[lower]
    if lower.startswith(GCP_MEMBER_PREFIXES):
        return False
    return "unknown"


def gcp_acl_entity_state(value):
    """ACL entity → 'allUsers' / 'allAuthenticatedUsers' / False / None / 'unknown'."""
    if value is None or is_unresolved(value) or isinstance(value, (list, dict)):
        return None
    lower = string_value(value).strip().lower()
    if lower in ("allusers", "allauthenticatedusers"):
        return GCP_PUBLIC_MEMBERS[lower]
    if lower.startswith(GCP_ACL_ENTITY_PREFIXES):
        return False
    return "unknown"


def gcp_role_level(role):
    """역할 → 접근 수준 글자. 사용자 정의·Storage 외·변수면 None (권한 불명)."""
    if role is None or is_unresolved(role):
        return None
    lower = string_value(role).strip().lower()
    if lower in GCP_ROLE_LEVEL:
        return GCP_ROLE_LEVEL[lower]
    if lower.startswith("roles/storage."):
        return "Storage 역할"
    return None


def gcp_bucket_info(body):
    """버킷 → {'pap': 'enforced'|'inherited'|None, 'ubla': True|False|None, 'website': bool}."""
    pap = body.get("public_access_prevention")
    if pap is None:
        pap_state = "inherited"                        # provider 기본값 "inherited"
    elif is_unresolved(pap):
        pap_state = None
    else:
        text = string_value(pap).strip().lower()
        pap_state = {"enforced": "enforced", "inherited": "inherited", "unspecified": "inherited"}.get(text, None)
    ubla_value = body.get("uniform_bucket_level_access", body.get("bucket_policy_only"))
    ubla = False if ubla_value is None else bool_state(ubla_value)
    return {"pap": pap_state, "pap_raw": pap, "ubla": ubla, "website": bool(blocks(body.get("website")))}


def build_gcp_index(datas):
    """같은 폴더(모듈)의 버킷 색인과 google_iam_policy 데이터 소스."""
    by_ref, by_name, policies = {}, {}, {}
    for data in datas:
        for typ, name, body in resources(data):
            if typ != GCP_BUCKET:
                continue
            info = gcp_bucket_info(body)
            by_ref[name] = info
            literal = body.get("name")
            if literal is not None and not is_unresolved(literal):
                by_name.setdefault(string_value(literal), []).append(info)
        for typ, name, body in data_sources(data):
            if typ == "google_iam_policy":
                policies[name] = body
    return {"by_ref": by_ref, "by_name": by_name, "policies": policies}


def link_gcp_bucket(value, index):
    """IAM·ACL 의 bucket 값 → 같은 폴더의 버킷 정보. 참조 우선, 리터럴은 유일할 때만. 못 찾으면 None."""
    if value is None:
        return None
    match = _GCP_BUCKET_REF.match(str(value).strip())
    if match:
        return index["by_ref"].get(match.group(1))
    if is_unresolved(value):
        return None
    candidates = index["by_name"].get(string_value(value), [])
    return candidates[0] if len(candidates) == 1 else None


def make_gcp_context(datas, module_dir=None):
    return {"index": build_gcp_index(datas), "module_dir": module_dir}


def gcp_policy_bindings(value, ctx):
    """policy_data → (바인딩 목록 [(role, members, has_condition)], 문제) . 문제: None / 'unresolved' / 'unsupported'."""
    if value is None:
        return [], "unresolved"
    text = str(value).strip()
    match = _GCP_POLICY_DATA_REF.match(text)
    if match:
        body = ctx["index"]["policies"].get(match.group(1))
        if body is None:
            return [], "unsupported"                   # 다른 폴더(모듈)의 data 소스이거나 없음
        if "dynamic" in body:
            return [], "unresolved"
        out = []
        for binding in blocks(body.get("binding")):
            out.append((binding.get("role"), binding.get("members"), bool(blocks(binding.get("condition")))))
        return out, None
    decoded = None
    jsonenc = _JSONENCODE.match(text)
    file_call = _FILE_CALL.match(text)
    if jsonenc and "${" not in jsonenc.group(1):
        decoded = jsonenc.group(1)
    elif file_call:
        path = (ctx["module_dir"] / file_call.group(1)) if ctx.get("module_dir") else None
        if path is None or not path.is_file():
            return [], "unsupported"
        decoded = path.read_text(encoding="utf-8", errors="replace")
    elif "${" not in text:
        decoded = text                                  # 리터럴 JSON (heredoc)
    if decoded is None:
        return [], "unresolved"
    try:
        policy = json.loads(decoded)
    except ValueError:
        return [], "unresolved"
    bindings = policy.get("bindings") if isinstance(policy, dict) else None
    if not isinstance(bindings, list):
        return [], ("unresolved" if bindings is not None else None)
    out = []
    for binding in bindings:
        if not isinstance(binding, dict):
            return [], "unresolved"
        out.append((binding.get("role"), binding.get("members"), bool(binding.get("condition"))))
    return out, None


def gcp_exposure(principals, level_known, bucket, acl=False):
    """공개 부여의 exposure. 우선순위: (ACL) UBLA true → PAP enforced → 역할 불명 → 주체 종류."""
    if acl and bucket is not None and bucket["ubla"] is True:
        return "acl_disabled_by_uniform_access"
    if bucket is not None and bucket["pap"] == "enforced":
        return "blocked_by_public_access_prevention"
    if not level_known:
        return "undetermined"
    if "allUsers" in principals:
        return "public_access_possible"
    return "authenticated_users_access_possible"


# ---------------------------------------------------------------------------
# 검사 규칙
# ---------------------------------------------------------------------------

def scan_configuration(data, s3_links=None, azure_ctx=None, gcp_ctx=None):
    """Return rule violations (BLOCK) and undecidable items (REVIEW) for a parsed HCL document.

    azure_ctx: 같은 폴더(모듈)의 Azure Storage 색인과 azurerm 버전 판단 (make_azure_context).
    gcp_ctx  : 같은 폴더(모듈)의 GCP 버킷 색인과 google_iam_policy 데이터 소스 (make_gcp_context, v3 PR 6).
               없으면 이 파일 하나만으로 만든다 (scan_file·자가 점검 경로).
    """
    if s3_links is None:
        s3_links = collect_s3_links([data])
    if azure_ctx is None:
        azure_ctx = make_azure_context([data])
    if gcp_ctx is None:
        gcp_ctx = make_gcp_context([data])
    findings = []

    def add(rule, resource, reason, exposure=None):
        meta = RULES[rule]
        finding = {"rule": rule, "resource": resource, "reason": reason,
                   "cloud": meta["cloud"], "policy": meta["policy"],
                   "verdict": meta["verdict"]}
        if exposure is not None:                       # Azure·GCP Storage 규칙에만 붙는다
            finding["exposure"] = exposure
        findings.append(finding)

    def check_azapi_static_website(ref, parsed, props):
        """azapi blobServices: properties.staticWebsite.enabled 만 본다 (다른 Blob 서비스 설정은 무관)."""
        unknown = ("azapi blobServices 의 정적 웹사이트 설정을 확인할 수 없음"
                   "(body·properties·staticWebsite 가 변수·표현식) (검토 필요)")
        if parsed is None or (props is not None and not isinstance(props, dict)):
            add("AZURE_STORAGE_STATIC_WEBSITE", ref, unknown, "undetermined")
            return
        site = (props or {}).get("staticWebsite")
        if site is None:
            return                                      # 정적 웹사이트를 건드리지 않음
        if not isinstance(site, dict):
            add("AZURE_STORAGE_STATIC_WEBSITE", ref, unknown, "undetermined")
            return
        state = bool_state(site.get("enabled"))
        if state is True:
            add("AZURE_STORAGE_STATIC_WEBSITE", ref,
                "azapi: staticWebsite.enabled = true — $web 컨테이너는 계정의 익명 접근 설정과 무관하게 공개됨 "
                "— 의도된 공개인지 확인 필요 (검토 필요)", "intentional_static_website")
        elif state is None:
            add("AZURE_STORAGE_STATIC_WEBSITE", ref,
                "azapi: staticWebsite.enabled 값을 확인할 수 없음(변수·표현식·생략) (검토 필요)", "undetermined")

    def check_tls(ref, value, old_values, old_reason):
        """명시적인 TLS 1.0/1.1 → AZURE_OLD_TLS(BLOCK), 변수·표현식 → AZURE_TLS_UNRESOLVED(REVIEW).
        결과: 'old' / 'unknown' / None(생략·안전한 값·처음 보는 값)."""
        if value is None:
            return None
        if is_unresolved(value):
            return "unknown"
        if string_value(value).upper() in old_values:
            add("AZURE_OLD_TLS", ref, old_reason)
            return "old"
        return None

    def report_gcp_grants(rule, ref, grants, unknown, unsupported, bucket, where, acl):
        """grants: [(principal, role_text, level 또는 None, has_condition)] — 확정된 공개 부여.
        unknown: 확인 불가 값 목록, unsupported: 처음 보는 형식·분석 불가 목록."""
        if grants:
            principals = {g[0] for g in grants}
            level_known = all(g[2] is not None for g in grants)
            parts = []
            for principal, role_text, level, cond in grants:
                part = f"{principal} 에게 {role_text}"
                part += f" (공개 {level})" if level else " (권한 내용 불명: 사용자 정의·Storage 외·변수 역할)"
                if cond:
                    part += " [IAM 조건 있음 — Google은 공개 주체에 조건을 허용하지 않음]"
                parts.append(part)
            exposure = gcp_exposure(principals, level_known, bucket, acl)
            notes = {
                "blocked_by_public_access_prevention":
                    " — 연결된 버킷이 PAP enforced 라 실제로는 무력화되며, Google은 공개 주체 추가를 거부(412)해 배포가 실패할 수 있음",
                "acl_disabled_by_uniform_access":
                    " — 연결된 버킷이 균일 버킷 수준 접근(UBLA)이라 ACL 요청은 400으로 실패하고 효력이 없음",
            }
            kind = "ACL" if acl else "IAM"
            add(rule, ref, f"공개 주체에게 권한을 부여하는 {kind} 선언{where}: " + "; ".join(parts)
                + notes.get(exposure, "") + EXPOSURE_NOTE, exposure)
        elif unknown:
            add("GCP_STORAGE_PUBLIC_UNRESOLVED", ref,
                f"공개 주체 여부를 확인할 수 없음{where}: " + ", ".join(unknown) + " (검토 필요)", "undetermined")
        elif unsupported:
            add("GCP_STORAGE_UNSUPPORTED", ref,
                f"분석하지 못한 구성{where}: " + ", ".join(unsupported) + " (검토 필요)", "undetermined")

    def check_gcp_storage(typ, ref, body):
        idx = gcp_ctx["index"]
        if typ == GCP_BUCKET:
            info = gcp_bucket_info(body)
            site = (" 정적 웹사이트 설정(website)이 있으나 그 자체는 권한을 주지 않음 — 공개 부여는 IAM·ACL 에서 따로 검사."
                    if info["website"] else "")
            if info["pap"] == "inherited":
                given = "생략(기본값 inherited)" if info["pap_raw"] is None else "inherited"
                add("GCP_STORAGE_PAP_NOT_ENFORCED", ref,
                    f"공개 접근 방지(public_access_prevention)가 enforced 가 아님: {given}. "
                    "조직 정책(storage.publicAccessPrevention)에 따라 결정되어 Terraform 밖의 공개 부여를 "
                    "막는지 확인할 수 없음 (검토 필요)." + site, "undetermined")
            elif info["pap"] is None:
                add("GCP_STORAGE_PUBLIC_UNRESOLVED", ref,
                    "public_access_prevention 값을 확인할 수 없음(변수·표현식·알 수 없는 값) (검토 필요)." + site,
                    "undetermined")
            return

        bucket = link_gcp_bucket(body.get("bucket"), idx)
        where = ""
        folder = body.get("managed_folder")
        if folder is not None:
            where = f" (managed folder {string_value(folder)})"

        if typ in GCP_IAM_TYPES:
            if typ.endswith("_iam_policy"):
                bindings, problem = gcp_policy_bindings(body.get("policy_data"), gcp_ctx)
            elif typ.endswith("_iam_member"):
                bindings, problem = [(body.get("role"), [body.get("member")], bool(blocks(body.get("condition"))))], None
            else:
                bindings, problem = [(body.get("role"), body.get("members"), bool(blocks(body.get("condition"))))], None
            grants, unknown, unsupported = [], [], []
            if problem == "unresolved":
                unknown.append("policy_data(변수·표현식·해석 불가)")
            elif problem == "unsupported":
                unsupported.append("policy_data 가 같은 폴더(모듈)에 없는 data 소스·파일을 가리킴")
            for role, members, cond in bindings:
                role_text = string_value(role) if role is not None and not is_unresolved(role) else "변수·표현식 역할"
                if members is None or (not isinstance(members, list) and is_unresolved(members)):
                    unknown.append("구성원 목록(변수·표현식)")
                    continue
                for member in (members if isinstance(members, list) else [members]):
                    state = gcp_member_state(member)
                    if state in ("allUsers", "allAuthenticatedUsers"):
                        grants.append((state, f"역할 {role_text}", gcp_role_level(role), cond))
                    elif state is None:
                        unknown.append("구성원(변수·표현식)")
                    elif state == "unknown":
                        unsupported.append(f"처음 보는 구성원 형식 {string_value(member)}")
            report_gcp_grants("GCP_STORAGE_PUBLIC_IAM", ref, grants, unknown, unsupported, bucket, where, False)
            return

        grants, unknown, unsupported = [], [], []
        if typ in GCP_ACL_LIST_TYPES:
            for key in ("predefined_acl", "default_acl"):
                value = body.get(key)
                if value is None:
                    continue
                if is_unresolved(value):
                    unknown.append(f"{key}(변수·표현식)")
                    continue
                public = GCP_PUBLIC_PREDEFINED.get(string_value(value).strip().lower())
                if public:
                    grants.append((public[0], f"{key} = {string_value(value)}", public[1], False))
            entries = body.get("role_entity")
            if entries is not None and not isinstance(entries, list):
                unknown.append("role_entity(변수·표현식)")
                entries = []
            for entry in entries or []:
                if is_unresolved(entry):
                    unknown.append("role_entity 항목(변수·표현식)")
                    continue
                text = string_value(entry)
                if ":" not in text:
                    unsupported.append(f"처음 보는 role_entity 형식 {text}")
                    continue
                role, entity = text.split(":", 1)
                state = gcp_acl_entity_state(entity)
                if state in ("allUsers", "allAuthenticatedUsers"):
                    grants.append((state, f"ACL {role}", GCP_ACL_ROLE_LEVEL.get(role.strip().lower()), False))
                elif state == "unknown":
                    unsupported.append(f"처음 보는 ACL entity {entity}")
        else:                                           # *_access_control: entity + role
            state = gcp_acl_entity_state(body.get("entity"))
            role = body.get("role")
            level = None if role is None or is_unresolved(role) else GCP_ACL_ROLE_LEVEL.get(string_value(role).lower())
            role_text = string_value(role) if role is not None and not is_unresolved(role) else "변수·표현식 역할"
            if state in ("allUsers", "allAuthenticatedUsers"):
                grants.append((state, f"ACL {role_text}", level, False))
            elif state is None:
                unknown.append("entity(변수·표현식)")
            elif state == "unknown":
                unsupported.append(f"처음 보는 ACL entity {string_value(body.get('entity'))}")
        report_gcp_grants("GCP_STORAGE_PUBLIC_ACL", ref, grants, unknown, unsupported, bucket, where, True)

    def check_azure_storage(typ, name, ref, body):
        index = azure_ctx["index"]
        if typ == STORAGE_ACCOUNT:
            verdict, why, effective = evaluate_storage_account(body, azure_ctx["default"], azure_ctx["note"])
            network = NETWORK_LABEL[account_network_state(body, index["network_rules"].get(name, []))]
            if verdict == "BLOCK":
                linked = index["container_states"].get(name, [])
                exposure = ("anonymous_access_configured" if "public" in linked
                            else "public_access_possible")
                add("AZURE_STORAGE_PUBLIC_ALLOWED", ref,
                    f"{why} [네트워크: {network}, 판정과 무관]{EXPOSURE_NOTE}", exposure)
            elif verdict == "REVIEW":
                add("AZURE_STORAGE_PUBLIC_UNRESOLVED", ref, why + " (검토 필요)", "undetermined")
            if blocks(body.get("static_website")):
                add("AZURE_STORAGE_STATIC_WEBSITE", ref,
                    "정적 웹사이트 활성화: $web 컨테이너는 계정의 익명 접근 설정과 무관하게 공개됨 "
                    "— 의도된 공개인지 확인 필요 (검토 필요)", "intentional_static_website")
            if any("static_website" in dyn for dyn in blocks(body.get("dynamic", []))):
                add("AZURE_STORAGE_STATIC_WEBSITE", ref,
                    "dynamic \"static_website\" 블록이라 정적 웹사이트 활성 여부를 확인할 수 없음 (검토 필요)",
                    "undetermined")
        elif typ == STORAGE_CONTAINER:
            state = container_access_state(body.get("container_access_type"))
            target = link_storage_account(body, index)
            if state == "public":
                if target is None:
                    exposure, where = "public_access_possible", "연결된 계정을 확인할 수 없음"
                else:
                    _v, _w, effective = evaluate_storage_account(
                        index["accounts"][target], azure_ctx["default"], azure_ctx["note"])
                    exposure = {True: "anonymous_access_configured",
                                False: "blocked_by_account_setting"}.get(effective, "public_access_possible")
                    where = f"연결된 계정 azurerm_storage_account.{target}"
                add("AZURE_STORAGE_CONTAINER_PUBLIC", ref,
                    f"컨테이너 접근 수준이 blob/container(익명 읽기 선언) — {where}{EXPOSURE_NOTE}", exposure)
            elif state is None:
                add("AZURE_STORAGE_PUBLIC_UNRESOLVED", ref,
                    "컨테이너 접근 수준이 변수·표현식이라 확인할 수 없음 (검토 필요)", "undetermined")
        elif typ == STORAGE_STATIC_WEBSITE:
            add("AZURE_STORAGE_STATIC_WEBSITE", ref,
                "정적 웹사이트 자원: $web 컨테이너는 계정의 익명 접근 설정과 무관하게 공개됨 "
                "— 의도된 공개인지 확인 필요 (검토 필요)", "intentional_static_website")
        elif typ in AZAPI_TYPES:
            base = azapi_type_base(body)
            if base is None:
                add("AZURE_STORAGE_PUBLIC_UNRESOLVED", ref,
                    "azapi 자원의 type을 확인할 수 없어 Storage 공개 설정 여부를 판단할 수 없음 (검토 필요)",
                    "undetermined")
                return
            if base == ARM_DEPLOYMENT:
                raw = body.get("body")
                state = template_text_state(raw, azure_ctx["module_dir"])
                if state != "clear":
                    add("AZURE_STORAGE_UNSUPPORTED", ref, {
                        "storage": "ARM 배포(azapi) 안의 Storage 설정은 해석하지 않음",
                        "linked": "ARM 배포(azapi)가 연결 템플릿(templateLink)을 불러와 내용을 확인할 수 없음",
                    }.get(state, "ARM 배포(azapi) 내용을 확인할 수 없음"), "undetermined")
                return
            if base not in (ARM_STORAGE_ACCOUNT, ARM_STORAGE_CONTAINER, ARM_BLOB_SERVICE):
                return                                  # Storage 와 무관한 azapi 자원
            parsed = azapi_body(body)
            props = parsed.get("properties") if isinstance(parsed, dict) else None
            if base == ARM_BLOB_SERVICE:
                check_azapi_static_website(ref, parsed, props)
                return
            if parsed is None or (props is not None and not isinstance(props, dict)):
                add("AZURE_STORAGE_PUBLIC_UNRESOLVED", ref,
                    "azapi body가 jsonencode·변수 등이라 공개 설정을 확인할 수 없음 (검토 필요)", "undetermined")
                return
            props = props or {}
            if base == ARM_STORAGE_ACCOUNT:
                if "allowBlobPublicAccess" not in props:
                    if typ == "azapi_resource":
                        add("AZURE_STORAGE_PUBLIC_UNRESOLVED", ref,
                            "azapi 계정에 allowBlobPublicAccess가 없어 Azure 서비스 기본값을 단정할 수 없음 (검토 필요)",
                            "undetermined")
                    return                              # update_resource 는 적은 속성만 바꿈
                state = bool_state(props["allowBlobPublicAccess"])
                if state is True:
                    add("AZURE_STORAGE_PUBLIC_ALLOWED", ref,
                        f"azapi: allowBlobPublicAccess = true{EXPOSURE_NOTE}", "public_access_possible")
                elif state is None:
                    add("AZURE_STORAGE_PUBLIC_UNRESOLVED", ref,
                        "azapi: allowBlobPublicAccess 값을 확인할 수 없음 (검토 필요)", "undetermined")
            else:
                value = props.get("publicAccess")
                if value is None:
                    return                              # 새 컨테이너 기본값은 비공개
                if is_unresolved(value):
                    add("AZURE_STORAGE_PUBLIC_UNRESOLVED", ref,
                        "azapi: publicAccess 값을 확인할 수 없음 (검토 필요)", "undetermined")
                elif string_value(value).lower() in ("blob", "container"):
                    add("AZURE_STORAGE_CONTAINER_PUBLIC", ref,
                        f"azapi: 컨테이너 publicAccess = {string_value(value)}{EXPOSURE_NOTE}",
                        "public_access_possible")
                elif string_value(value).lower() != "none":
                    add("AZURE_STORAGE_PUBLIC_UNRESOLVED", ref,
                        "azapi: publicAccess 값이 알려진 값이 아님 (검토 필요)", "undetermined")
        elif typ in TEMPLATE_DEPLOYMENT_TYPES:
            if body.get("template_spec_version_id") is not None:
                state = "unknown"
            else:
                state = template_text_state(body.get("template_content"), azure_ctx["module_dir"])
            if state != "clear":
                add("AZURE_STORAGE_UNSUPPORTED", ref, {
                    "storage": "ARM 템플릿 안의 Storage 계정 설정은 해석하지 않음 (검토 필요)",
                    "linked": "ARM 템플릿이 연결 템플릿(templateLink)을 불러와 내용을 확인할 수 없음 (검토 필요)",
                }.get(state, "ARM 템플릿 내용을 확인할 수 없음 (검토 필요)"), "undetermined")

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

    def check_azure_rule(ref, rule, where):
        verdict, unknown = evaluate_azure_rule(rule)
        if verdict == "BLOCK":
            add("AZURE_PUBLIC_ADMIN_PORT", ref,
                "인터넷 전체에서 SSH(22) 또는 RDP(3389) 인바운드 허용" + where)
        elif verdict == "REVIEW":
            add("AZURE_ADMIN_PORT_UNRESOLVED", ref,
                "값을 확인할 수 없어 관리자 포트 공개 여부를 판단할 수 없음: "
                + ", ".join(unknown) + where + " (검토 필요)")

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

        # Azure NSG allows public SSH/RDP (CG-NET-01).
        if typ == "azurerm_network_security_rule":
            check_azure_rule(ref, body, "")
        if typ == "azurerm_network_security_group":
            inline_rules = body.get("security_rule")
            # security_rule 블록 안의 개별 변수는 아래 check_azure_rule이
            # 5개 위험 조건을 따로 판단한다. 목록 전체가 불투명한 표현식일 때만
            # 여기서 REVIEW를 추가한다 (중복/과잉 차단 방지).
            opaque_rule = (
                inline_rules is not None
                and (not isinstance(inline_rules, (list, dict))
                     or (isinstance(inline_rules, list)
                         and any(not isinstance(item, dict) for item in inline_rules)))
            )
            if opaque_rule:
                add("AZURE_ADMIN_PORT_UNRESOLVED", ref,
                    "security_rule 전체가 변수·표현식이라 관리자 포트 공개 여부를 확인할 수 없음 (검토 필요)")
            for index, rule in enumerate(blocks(inline_rules), start=1):
                label = string_value(rule.get("name", f"{index}번째"))
                check_azure_rule(ref, rule, f" (내부 규칙 '{label}')")
            for dyn in blocks(body.get("dynamic", [])):
                if "security_rule" in dyn:
                    add("AZURE_ADMIN_PORT_UNRESOLVED", ref,
                        "dynamic \"security_rule\" 블록은 지원하지 않아 규칙 내용을 확인할 수 없음 (검토 필요)")

        # GCP firewall allows public SSH/RDP (CG-NET-01).
        if typ == "google_compute_firewall":
            verdict, unknown = evaluate_gcp_firewall(body)
            if verdict == "BLOCK":
                add("GCP_PUBLIC_ADMIN_PORT", ref,
                    "인터넷 전체(0.0.0.0/0 또는 ::/0)에서 SSH(22) 또는 RDP(3389) 접속 허용")
            elif verdict == "REVIEW":
                add("GCP_ADMIN_PORT_UNRESOLVED", ref,
                    "값을 확인할 수 없어 관리자 포트 공개 여부를 판단할 수 없음: "
                    + ", ".join(unknown) + " (검토 필요)")

        # GCP hierarchical/global/regional firewall policy rules (CG-NET-01).
        # 지원하는 리소스의 단순 설정은 PASS/BLOCK을 판정하고 불명확한 경우 REVIEW.
        if typ in GCP_FIREWALL_POLICY_RULE_TYPES:
            verdict, unknown = evaluate_gcp_firewall_policy_rule(body)
            if verdict == "BLOCK":
                add("GCP_FIREWALL_POLICY_PUBLIC_ADMIN_PORT", ref,
                    "GCP 방화벽 정책 규칙이 인터넷 전체에서 TCP 22/3389 인바운드를 허용하도록 설정됨")
            elif verdict == "REVIEW":
                add("GCP_FIREWALL_POLICY_UNRESOLVED", ref,
                    "GCP 방화벽 정책 규칙을 확정 판정할 수 없음: "
                    + ", ".join(unknown) + " (검토 필요)")

        if is_other_gcp_firewall_policy_rule_type(typ):
            add("GCP_FIREWALL_POLICY_UNRESOLVED", ref,
                "분석을 지원하지 않는 GCP 방화벽 정책 규칙 자원 유형(규칙 내용을 확인하지 못함): "
                + typ + " (검토 필요)")

        # Azure Storage public access (CG-STO-01).
        check_azure_storage(typ, name, ref, body)

        # GCP Cloud Storage public access (CG-STO-01, v3 PR 6).
        if typ == GCP_BUCKET or typ in GCP_IAM_TYPES or typ in GCP_ACL_LIST_TYPES or typ in GCP_ACL_ENTITY_TYPES:
            check_gcp_storage(typ, ref, body)

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
            # v3 PR 5: 저장소 계정은 min_tls_version = "TLS1_0"/"TLS1_1" 형식을 쓴다.
            # 값이 변수·표현식이면 오래된 TLS 를 허용할 수도 있으므로 REVIEW (생략은 판단하지 않음)
            tls = check_tls(ref, body.get("minimum_tls_version"), ("1.0", "1.1"),
                            "오래된 TLS 최소 버전(1.0 또는 1.1) 허용")
            if tls != "old":
                tls2 = check_tls(ref, body.get("min_tls_version"), ("TLS1_0", "TLS1_1"),
                                 "오래된 TLS 최소 버전(TLS1_0 또는 TLS1_1) 허용")
                if tls2 != "old" and "unknown" in (tls, tls2):
                    add("AZURE_TLS_UNRESOLVED", ref,
                        "TLS 최소 버전이 변수·표현식이라 1.0/1.1 허용 여부를 확인할 수 없음 (검토 필요)")

        # azapi 자원의 properties.minimumTlsVersion (Storage·Redis 등 ARM 공통 이름)
        if typ in AZAPI_TYPES:
            parsed = azapi_body(body)
            props = parsed.get("properties") if isinstance(parsed, dict) else None
            if isinstance(props, dict) and "minimumTlsVersion" in props:
                tls = check_tls(ref, props["minimumTlsVersion"], ("TLS1_0", "TLS1_1", "1.0", "1.1"),
                                "azapi: 오래된 TLS 최소 버전(minimumTlsVersion = TLS1_0/TLS1_1) 허용")
                if tls == "unknown":
                    add("AZURE_TLS_UNRESOLVED", ref,
                        "azapi: minimumTlsVersion 이 변수·표현식이라 1.0/1.1 허용 여부를 확인할 수 없음 (검토 필요)")

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
    for typ, name, body in resources(data):
        ref = f"{typ}.{name}"
        cloud = cloud_of(typ)
        targets = list(POLICY_TARGETS.items()) + [(("CG-STO-01", "azure"), None)]
        for (policy, target_cloud), target_types in targets:
            if target_types is None:
                matched = cloud == "azure" and is_azure_storage_check_target(typ, body)
            else:
                matched = cloud == target_cloud and (typ in target_types or
                    (policy == "CG-NET-01" and cloud == "gcp" and
                     is_other_gcp_firewall_policy_rule_type(typ)))
            if matched:
                status = worst(f["verdict"] for f in findings
                               if f["resource"] == ref and f["policy"] == policy)
                checks.append({"resource": ref, "cloud": cloud,
                               "policy": policy, "status": status})
    return checks


def policy_support_resources(policy, cloud):
    """지원 범위 표의 '검사 대상 자원 종류' (build_checks 가 실제로 기록하는 자원과 같은 출처)."""
    if (policy, cloud) == ("CG-STO-01", "azure"):
        return sorted({STORAGE_ACCOUNT, STORAGE_CONTAINER, STORAGE_STATIC_WEBSITE}
                      | AZAPI_TYPES | TEMPLATE_DEPLOYMENT_TYPES)
    resources = set(POLICY_TARGETS.get((policy, cloud), set()))
    if (policy, cloud) == ("CG-NET-01", "gcp"):
        resources |= set(GCP_FIREWALL_POLICY_RULE_TYPES)
    return sorted(resources)


def policy_matrix(results):
    """검사 결과(파일 목록) → 정책×클라우드 칸 목록. 각 칸: 지원 여부, 검사한 자원 수, 상태별 개수, 결과.

    결과: PASS(검사한 대상에서 위반 없음) / BLOCK / REVIEW / N/A(지원하지만 대상 자원 없음) / 미지원.
    ERROR 파일이 있으면 그 파일은 읽지 못했으므로 N/A 대신 '확인 불가(ERROR)' 로 표시한다.
    """
    has_error = any(r["status"] == "ERROR" for r in results)
    cells = []
    for policy in POLICY_NAMES:
        for cloud in POLICY_CLOUDS:
            checks = [c for r in results for c in r.get("checks", [])
                      if c["policy"] == policy and c["cloud"] == cloud]
            counts = {s: sum(c["status"] == s for c in checks) for s in ("PASS", "REVIEW", "BLOCK")}
            supported = (policy, cloud) in POLICY_SUPPORT
            if not supported:
                result = "미지원"
            elif not checks:
                result = "확인 불가(ERROR)" if has_error else "N/A"
            else:
                result = worst(c["status"] for c in checks)
            cells.append({"policy": policy, "cloud": cloud, "supported": supported, "checked": len(checks),
                          "counts": counts, "result": result,
                          "rules": sorted(r for r, m in RULES.items() if m["policy"] == policy and m["cloud"] == cloud),
                          "resources": policy_support_resources(policy, cloud),
                          "limits": POLICY_SUPPORT.get((policy, cloud), "구현 없음")})
    return cells


def load_tf(path):
    import hcl2  # Installation: py -m pip install -r requirements.txt
    with path.open("r", encoding="utf-8") as f:
        return hcl2.load(f)


def scan_file(path):
    """파일 1개의 위반·검토 목록 (self_test.py도 이 함수를 사용한다).

    파일 하나만 보고 판단하므로, S3 버킷과 공개 차단 설정은 같은 파일 안에서만 연결을 찾는다.
    """
    return scan_configuration(load_tf(path))


def scan_paths(tf_files):
    """.tf 파일 목록을 검사해 파일별 결과 목록을 돌려준다 (v3 PR 5에서 main 에서 분리, 동작 동일).

    1단계: 모든 파일을 먼저 읽는다 (S3 버킷과 공개 차단 설정, Storage 계정과 컨테이너가
           다른 파일에 있을 수 있음)
    2단계: 폴더(모듈)별로 S3 연결(v3 PR 6부터), Azure Storage 색인과 azurerm 버전 판단,
           GCP 버킷 색인(v3 PR 6)을 만든다
    3단계: 파일별로 검사한다
    """
    parsed, errors = {}, {}
    for path in tf_files:
        try:
            parsed[path] = load_tf(path)
        except Exception as exc:
            errors[path] = f"{type(exc).__name__}: {exc}"  # Fail closed: never a PASS.
    by_dir = {}
    for path, data in parsed.items():
        by_dir.setdefault(path.parent, []).append(data)
    # v3 PR 6: S3 버킷 ↔ 공개 차단 설정 연결도 Terraform 모듈(폴더) 경계 안에서만 한다.
    # (PR 5까지는 검사한 모든 폴더를 하나로 묶어, 다른 루트 모듈의 같은 이름 버킷을 잘못 연결할 수 있었다)
    s3_links = {d: collect_s3_links(datas) for d, datas in by_dir.items()}
    versions = resolve_version_contexts(by_dir) if by_dir else {}
    azure_ctx = {d: make_azure_context(datas, versions[d], d) for d, datas in by_dir.items()}
    gcp_ctx = {d: make_gcp_context(datas, d) for d, datas in by_dir.items()}

    results = []
    for path in tf_files:
        if path in errors:
            findings, checks, status, error = [], [], "ERROR", errors[path]
        else:
            findings = scan_configuration(parsed[path], s3_links[path.parent], azure_ctx[path.parent],
                                          gcp_ctx[path.parent])
            checks = build_checks(parsed[path], findings)
            status, error = file_status(findings), None
        results.append({"file": str(path), "status": status,
                        "findings": findings, "checks": checks, "error": error})
    return results


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

    results = scan_paths(tf_files)
    for result in results:
        status, path, findings, error = result["status"], result["file"], result["findings"], result["error"]
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
