"""웹 노출 비밀/백업 파일 '읽기 전용' 열거 — 발판 전에 HTTP 로 자격을 수확하기 위한 재료.

자동 루트 실패의 한 축: 많은 머신(예: 인증 필요 RCE)은 **먼저 자격을 얻어야** 다음 단계로
간다. 설정/백업 파일이 웹에 잘못 노출돼 있으면, 셸 없이도 평문 자격이 그대로 떨어진다.
이 모듈은 그 '노출 후보 경로'와 **무해한 GET 명령**(curl -s)만 생성한다(생성 전용).

안전 경계(불변):
  · 전부 **읽기 전용 GET**(curl -s) — 쓰기·인증·주입·실행 없음. gobuster/curl 열거와 동일 위험군.
  · 실제 네트워크 발사는 오케스트레이터의 3관문(검증·범위·승인)을 그대로 거친다.
  · 수확(본문→자격)은 기존 _harvest_creds 경로가 원시출력에서 수행한다.
"""
from __future__ import annotations

import re

# 제품 무관하게 흔히 자격·비밀이 새는 경로(오설정·편집기 백업·VCS 노출). 상대경로.
_GENERIC_PATHS: list[str] = [
    ".env", ".env.bak", ".env.save", ".env.old", ".env.local",
    "config.php.bak", "config.php~", "config.php.save", "config.php.old",
    "config.inc.php.bak", "config.json", "config.yml", "config.yaml",
    ".git/config", ".git/HEAD", ".svn/entries",
    "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "dump.sql",
    "wp-config.php.bak", "wp-config.php~",
    ".htpasswd", ".DS_Store",
]

# 제품별 노출 설정/백업 후보(관리 경로 포함).
_PRODUCT_PATHS: dict[str, list[str]] = {
    "freepbx": ["admin/config.php.bak", "admin/config.php~",
                "admin/bootstrap.php.bak", "amportal.conf", ".ampconfig",
                "admin/.env", "admin/libraries/db_connect.php.bak"],
    "elastix": ["amportal.conf", "admin/config.php.bak"],
    "wordpress": ["wp-config.php.bak", "wp-config.php~", "wp-config.php.save",
                  "wp-config.php.old", ".wp-config.php.swp"],
    "joomla": ["configuration.php.bak", "configuration.php~",
               "configuration.php.save", "configuration.php-dist.bak"],
    "drupal": ["sites/default/settings.php.bak", "sites/default/settings.php~"],
    "nextcloud": ["config/config.php.bak", "config/config.php~"],
    "gitea": ["custom/conf/app.ini.bak", "app.ini"],
    "grafana": ["conf/defaults.ini", "grafana.ini.bak"],
}


def exposed_paths(product: str = "") -> list[str]:
    """노출 비밀/백업 후보 경로 목록(제품별 + 일반). 중복 제거, 선행 슬래시 정규화."""
    paths: list[str] = []
    paths += _PRODUCT_PATHS.get((product or "").lower().strip(), [])
    paths += _GENERIC_PATHS
    out: list[str] = []
    seen: set[str] = set()
    for p in paths:
        p = p.lstrip("/").strip()
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


# 셸/헤더 인젝션 방지 — 호스트명으로 허용할 문자(영숫자·점·하이픈)만.
_HOST_SAFE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def secret_read_commands(bases: list[str], product: str = "",
                         vhosts: list[str] | None = None,
                         limit: int = 24) -> list[str]:
    """베이스 URL × 노출 후보 경로로 무해한 GET 명령(curl -s)을 만든다(생성 전용 — 실행 아님).
    `-s`(조용히) · `--max-time`(지연 방지) · `-k`(https 자가서명 대비). 상위 `limit` 개로 제한.

    vhost 기반 앱(예: connected.htb)은 IP 기본 vhost 로는 404/301 만 떨어진다 → 등록된
    vhost 가 있으면 `-H "Host: <vhost>"` 를 붙여 **실제 앱**을 때린다(그 경우 IP-만 프로브는
    생략 — 어차피 못 본다). 호스트명은 인젝션 방지로 안전 문자만 허용."""
    bases = [b.rstrip("/") for b in (bases or []) if b]
    if not bases:
        return []
    safe_vhosts = [v for v in (vhosts or []) if v and _HOST_SAFE.match(v)]
    # vhost 가 있으면 Host 헤더로만(앱이 거기 있음), 없으면 헤더 없이 IP 직타.
    hosts: list[str] = safe_vhosts if safe_vhosts else [""]
    paths = exposed_paths(product)
    cmds: list[str] = []
    seen: set[str] = set()
    for path in paths:                       # 경로 바깥 루프 → 베이스/vhost 간 공평 분배
        for base in bases:
            for host in hosts:
                hdr = f' -H "Host: {host}"' if host else ""
                cmd = f"curl -s -k --max-time 10{hdr} {base}/{path}"
                if cmd not in seen:
                    seen.add(cmd)
                    cmds.append(cmd)
                if len(cmds) >= limit:
                    return cmds
    return cmds
