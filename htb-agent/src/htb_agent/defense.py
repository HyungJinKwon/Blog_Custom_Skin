"""공격↔방어 미러 — 실제 '탐지/공략한 취약점'마다 블루팀 탐지·완화를 짝지어 생성한다.

기존 writeup 의 블루팀 섹션은 '관측된 포트' 기준이다. 이 모듈은 한 축을 더한다: **실제로
식별·공략한 취약점/기법**(CVE·CWE·vuln 규칙 매칭·웹앱 제품)마다 "이렇게 탐지하고 이렇게
막는다"를 붙여, 레드 라이트업이 그대로 블루팀 가이드가 되게 한다(ARTEX 의 공격↔방어 미러
문서 아이디어를 클린룸 재구현 — 코드 미사용). 생성 전용 — 문자열만 만든다.

용어 사용자 선호(§7): SIEM·Snort/Suricata·Wireshark·체크리스트 지표를 유지한다.
"""
from __future__ import annotations

from dataclasses import dataclass

# CWE → (탐지 관점, 완화 관점). 흔한 웹/인프라 취약점 위주(근거 있는 일반 통제).
_CWE_DEFENSE: dict[str, tuple[str, str]] = {
    "CWE-89":  ("DB 오류·UNION/sleep 패턴, 비정상 쿼리량 급증(SIEM 상관)",
                "파라미터라이즈드 쿼리/ORM, 입력 검증, 최소권한 DB 계정, WAF 규칙"),
    "CWE-78":  ("웹→셸 프로세스 생성(의심 부모-자식), 아웃바운드 역쉘 연결",
                "입력을 셸로 넘기지 않기(exec 배열), 알로리스트, 애플리케이션 샌드박스"),
    "CWE-79":  ("비정상 `<script>`/이벤트 핸들러 반사, CSP 위반 리포트",
                "출력 인코딩, CSP, 신뢰 경계에서 입력 정제"),
    "CWE-22":  ("`../`·인코딩된 경로 순회 토큰, 비정상 파일 접근",
                "정규화 후 알로리스트 경로 검증, chroot/컨테이너 격리"),
    "CWE-434": ("업로드 후 웹루트 내 실행형 확장자 생성·접근",
                "확장자/콘텐츠타입 검증, 웹루트 밖 저장, 실행권한 제거"),
    "CWE-98":  ("원격 URL include·wrapper(php://, data://) 사용 흔적",
                "allow_url_include=Off, include 경로 알로리스트"),
    "CWE-287": ("동일 계정 다발 로그인 실패→성공, 비정상 인증 흐름",
                "MFA, 계정 잠금/레이트리밋, 기본자격 제거"),
    "CWE-200": ("열거성 요청 급증(사용자/경로/버전 probe)",
                "오류 메시지 일반화, 응답 차이 제거, 레이트리밋"),
    "CWE-862": ("권한 없는 주체의 관리 기능/객체 접근(IDOR)",
                "객체 단위 인가 체크, 서버측 권한 재확인"),
    "CWE-502": ("역직렬화 가젯 페이로드(매직바이트/클래스명) 유입",
                "신뢰 불가 역직렬화 금지, 서명/알로리스트, 안전 포맷(JSON)"),
    "CWE-918": ("내부 IP/메타데이터 엔드포인트로의 서버발 요청",
                "아웃바운드 알로리스트, 메타데이터 차단, URL 스킴 제한"),
    "CWE-362": ("짧은 간격의 경쟁 조건 유발 반복 요청",
                "원자적 연산/락, 서버측 상태 검증"),
}

# 기법 키워드(취약점 이름·제목에 등장) → (탐지, 완화). CVE/CWE 가 없을 때의 보강.
_TECH_DEFENSE: list[tuple[tuple[str, ...], str, str]] = [
    (("사용자 열거", "username enum", "user enum"),
     "인증 전 응답 차이·타이밍 차이를 노리는 열거 요청 급증",
     "응답/타이밍 균일화, 레이트리밋, 유효 계정 노출 최소화"),
    (("rce", "remote code", "command exec", "원격 코드", "명령 실행"),
     "웹 프로세스의 비정상 자식 프로세스·아웃바운드 역쉘",
     "패치/업그레이드, 입력-셸 분리, 최소권한 실행, egress 제한"),
    (("sql", "sqli", "injection"),
     "DB 오류/부울·시간 기반 패턴, 비정상 쿼리",
     "파라미터라이즈드 쿼리, WAF, 최소권한 DB"),
    (("auth bypass", "인증 우회", "authentication bypass"),
     "정상 로그인 없이 보호 리소스 접근 성공",
     "서버측 인가 재확인, 세션 무결성, 기본자격 제거"),
    (("default cred", "기본 자격", "weak password", "약한 자격"),
     "기본/약한 자격으로의 로그인 성공, 크리덴셜 스터핑",
     "기본자격 제거·강제 변경, MFA, 계정 잠금"),
    (("lfi", "file inclusion", "path travers", "경로 순회"),
     "`../`·wrapper 토큰, 민감 파일 접근",
     "경로 정규화+알로리스트, 격리, 민감파일 접근권한 축소"),
    (("upload", "업로드"),
     "웹루트 내 실행형 파일 생성·실행",
     "콘텐츠 검증, 웹루트 밖 저장, 실행권한 제거"),
]


@dataclass
class DefenseItem:
    vuln: str          # 취약점/기법 라벨
    detect: str        # 탐지 관점
    remediate: str     # 완화 관점


def _cwe_ids(report) -> list[str]:
    return list(getattr(report, "detected_cwe", []) or [])


def defense_items(report) -> list[DefenseItem]:
    """report 의 CVE/CWE·vuln 매칭·웹앱 제품에서 '탐지/공략한 취약점'마다 방어 항목을 만든다.
    근거 없는 항목은 만들지 않는다(매칭된 것만). 중복(같은 vuln 라벨) 제거."""
    items: list[DefenseItem] = []
    seen: set[str] = set()

    def _add(vuln: str, detect: str, remediate: str) -> None:
        key = vuln.strip().lower()
        if key and key not in seen:
            seen.add(key)
            items.append(DefenseItem(vuln, detect, remediate))

    # 1) CWE 기반(가장 구체적)
    for cwe in _cwe_ids(report):
        d = _CWE_DEFENSE.get(cwe.upper())
        if d:
            _add(cwe.upper(), d[0], d[1])

    # 2) vuln 규칙 매칭(이름·CVE)에서 기법 키워드 추론
    for m in getattr(report, "vuln_matches", []) or []:
        name = (getattr(m, "name", "") or "")
        low = name.lower()
        # 매칭의 CWE 가 있으면 우선 CWE 사전으로
        for cwe in getattr(m, "cwe", []) or []:
            d = _CWE_DEFENSE.get(str(cwe).upper())
            if d:
                _add(f"{name} ({cwe})" if name else str(cwe), d[0], d[1])
        for keys, det, rem in _TECH_DEFENSE:
            if any(k in low for k in keys):
                _add(name or keys[0], det, rem)
                break

    # 3) 웹앱 제품이 식별됐으면 n-day 노출 일반 통제 1건(근거: 버전 노출)
    prod = ""
    if getattr(report, "world", None) is not None:
        prod = getattr(report.world, "web_product", "") or ""
    if prod:
        _add(f"{prod} n-day 노출",
             "알려진 취약 버전 핑거프린트 요청, 공개 PoC 트래픽 패턴",
             "최신 버전 패치, 버전 배너 숨김, 관리 경로 접근통제·인증 강화")
    return items


def render_markdown(report) -> str:
    """취약점별 탐지·완화 미러를 Markdown 표로. 항목 없으면 정직하게 안내(지어내지 않음)."""
    items = defense_items(report)
    if not items:
        return ("_(식별·공략된 취약점이 없어 취약점별 미러 생략 — 포트 기준 지표만 참고. "
                "CVE/CWE 가 확인되면 자동 생성)_")
    rows = ["| 취약점/기법 | 탐지(Blue Team) | 완화(Remediation) |",
            "|---|---|---|"]
    for it in items:
        v = it.vuln.replace("|", "·")
        det = it.detect.replace("|", "·")
        rem = it.remediate.replace("|", "·")
        rows.append(f"| {v} | {det} | {rem} |")
    return "\n".join(rows)
