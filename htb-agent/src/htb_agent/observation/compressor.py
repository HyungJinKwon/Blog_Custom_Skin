"""
Observation Compressor — 구조화 결과를 LLM 용으로 압축
=======================================================

파싱된 구조(NmapHost/HttpResult)를 LLM 컨텍스트에 넣기 좋은 **최소 요약**으로
압축한다. 원문 전체(수백~수천 줄)를 넣지 않아 토큰을 크게 절감한다(비용·속도).
또한 OS 판정을 바로 붙여 "지금 무엇을 아는가"를 한눈에 보이게 한다.
"""

from __future__ import annotations

from ..target_profiler import ProfileResult, classify
from .parsers import NmapHost


def profile_from_nmap(host: NmapHost) -> ProfileResult:
    """파싱된 호스트에서 바로 OS/역할 판정."""
    pi = host.to_profile_inputs()
    return classify(pi["open_ports"], banners=pi["banners"],
                    script_output=pi["script_output"])
