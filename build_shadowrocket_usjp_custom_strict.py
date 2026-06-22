#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Convert a Johnshall Shadowrocket .conf into a custom Shadowrocket .conf.

Default source:
  https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_cnip.conf

Default behavior:
  - Keep Shadowrocket .conf format, not Clash/Mihomo YAML.
  - Copy [General] from source by default.
  - Strictly match high-rate nodes as >=10x by default, not only 10x/20x.
  - Generate only these proxy groups:
      Proxy / 日美节点 / 美国节点 / 日本节点 / 韩国节点 / 港澳节点 / 10x+节点
  - OpenAI / ChatGPT / Codex / iOS ChatGPT App -> 美国节点
  - Anthropic / Claude -> 美国节点
  - Source rules with Proxy / PROXY -> 日美节点
  - DIRECT remains DIRECT
  - REJECT remains REJECT
  - FINAL is forced to 日美节点 by default, so unknown non-domestic traffic is proxied.
  - No Nextin / Clash / Mihomo YAML is generated.

Usage:
  python3 build_shadowrocket_usjp_custom.py --output Shadowrocket_USJP_Custom.conf

Optional:
  python3 build_shadowrocket_usjp_custom.py \
    --source-url https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_top500_banlist.conf \
    --output Shadowrocket_USJP_Custom.conf

Strict high-rate matching:
  Default high-rate regex matches >=10x, such as 10x, 10.5x, 20x, 100x.

If you want to drop ad-block REJECT rules from a *_ad.conf source:
  python3 build_shadowrocket_usjp_custom.py --drop-reject --output Shadowrocket_USJP_Lite.conf
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


DEFAULT_SOURCE_URL = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_cnip.conf"
DEFAULT_HIGH_REGEX = r"(?:1[0-9]|[2-9][0-9]|[1-9][0-9]{2,})(?:\.\d+)?\s*x"
TEST_URL = "http://www.gstatic.com/generate_204"


OPENAI_RULES = [
    "# ===== OpenAI / ChatGPT / Codex / iOS ChatGPT App -> 美国节点 =====",
    "DOMAIN,ios.chat.openai.com,美国节点",
    "DOMAIN,chat.openai.com,美国节点",
    "DOMAIN,ws.chatgpt.com,美国节点",
    "DOMAIN,auth0.openai.com,美国节点",
    "DOMAIN,setup.auth.openai.com,美国节点",
    "DOMAIN,challenges.cloudflare.com,美国节点",
    "DOMAIN-SUFFIX,chatgpt.com,美国节点",
    "DOMAIN-SUFFIX,openai.com,美国节点",
    "DOMAIN-SUFFIX,auth.openai.com,美国节点",
    "DOMAIN-SUFFIX,oaistatic.com,美国节点",
    "DOMAIN-SUFFIX,oaiusercontent.com,美国节点",
    "DOMAIN-SUFFIX,oaistatsig.com,美国节点",
    "DOMAIN-SUFFIX,openaimerge.com,美国节点",
    "DOMAIN-SUFFIX,workos.com,美国节点",
    "DOMAIN-SUFFIX,workoscdn.com,美国节点",
    "",
]

ANTHROPIC_RULES = [
    "# ===== Anthropic / Claude -> 美国节点 =====",
    "DOMAIN-SUFFIX,anthropic.com,美国节点",
    "DOMAIN-SUFFIX,anthropicusercontent.com,美国节点",
    "DOMAIN-SUFFIX,claude.ai,美国节点",
    "DOMAIN-SUFFIX,claude.com,美国节点",
    "",
]


@dataclass(frozen=True)
class SectionedConf:
    general: List[str]
    rules: List[str]


def download_text(url: str, timeout: int = 30) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 shadowrocket-rule-converter/1.0",
            "Accept": "text/plain,*/*",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    # Johnshall files are UTF-8.
    return raw.decode("utf-8")


def split_sections(text: str) -> SectionedConf:
    current: Optional[str] = None
    general: List[str] = []
    rules: List[str] = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n\r")
        stripped = line.strip()

        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped.lower()
            continue

        if current == "[general]":
            general.append(line)
        elif current == "[rule]":
            rules.append(line)

    return SectionedConf(general=general, rules=rules)


def split_inline_comment(line: str) -> Tuple[str, str]:
    """
    Split a Shadowrocket rule line into rule part and inline comment.
    We only treat a # preceded by whitespace as a comment marker.
    """
    m = re.search(r"\s+#", line)
    if not m:
        return line.rstrip(), ""
    return line[: m.start()].rstrip(), line[m.start() :].rstrip()


def normalize_policy(policy: str) -> str:
    p = policy.strip()
    lower = p.lower()
    if lower == "proxy":
        return "日美节点"
    if lower == "direct":
        return "DIRECT"
    if lower in {"reject", "reject-tinygif", "reject-dict"}:
        # Shadowrocket supports several rejection actions; keep the exact
        # specialized action if source uses it, otherwise normalize plain reject.
        return p if lower != "reject" else "REJECT"
    return p


def convert_rule_line(
    line: str,
    final_policy: str,
    drop_reject: bool,
) -> Optional[str]:
    stripped = line.strip()

    # Preserve comments and blank lines.
    if not stripped or stripped.startswith("#"):
        return line.rstrip()

    rule_part, inline_comment = split_inline_comment(line)
    if not rule_part:
        return line.rstrip()

    fields = [f.strip() for f in rule_part.split(",")]
    if not fields:
        return line.rstrip()

    rule_type = fields[0].upper()

    # FINAL / MATCH-like lines in Shadowrocket are usually FINAL,<POLICY>.
    if rule_type == "FINAL":
        return f"FINAL,{final_policy}" + (f" {inline_comment}" if inline_comment else "")

    # Common no-resolve form:
    #   IP-CIDR,1.1.1.1/32,Proxy,no-resolve
    policy_index = len(fields) - 1
    if fields[-1].lower() == "no-resolve" and len(fields) >= 3:
        policy_index = len(fields) - 2

    old_policy = fields[policy_index].strip()
    new_policy = normalize_policy(old_policy)

    if drop_reject and new_policy.upper().startswith("REJECT"):
        return None

    fields[policy_index] = new_policy
    return ",".join(fields) + (f" {inline_comment}" if inline_comment else "")


def convert_rules(
    source_rules: Iterable[str],
    final_policy: str = "日美节点",
    drop_reject: bool = False,
) -> List[str]:
    converted: List[str] = []

    converted.extend(OPENAI_RULES)
    converted.extend(ANTHROPIC_RULES)
    converted.append("# ===== Johnshall source rules, with Proxy/PROXY mapped to 日美节点 =====")

    seen_final = False

    for line in source_rules:
        out = convert_rule_line(line, final_policy=final_policy, drop_reject=drop_reject)
        if out is None:
            continue
        if out.strip().upper().startswith("FINAL,"):
            seen_final = True
        converted.append(out)

    if not seen_final:
        converted.append("")
        converted.append(f"FINAL,{final_policy}")

    return converted


def negative_filter(region_regex: str, high_regex: str) -> str:
    """
    Shadowrocket has policy-regex-filter but not a separate exclude-filter.
    Use a single regex:
      - must contain the region keyword
      - must not contain the high-rate keyword
    """
    return f"(?i)^(?=.*({region_regex}))(?!.*({high_regex})).*$"


def build_proxy_groups(high_regex: str) -> List[str]:
    us = r"美国|美國|United States|\bUS\b|\bUSA\b"
    jp = r"日本|Japan|\bJP\b|JPN"
    kr = r"韩国|韓國|Korea|\bKR\b|KOR"
    hkmac = r"香港|Hong Kong|\bHK\b|HKG|澳门|澳門|Macao|Macau|\bMO\b"

    us_jp_filter = negative_filter(f"{us}|{jp}", high_regex)
    us_filter = negative_filter(us, high_regex)
    jp_filter = negative_filter(jp, high_regex)
    kr_filter = negative_filter(kr, high_regex)
    hkmac_filter = negative_filter(hkmac, high_regex)

    return [
        "[Proxy Group]",
        "# Proxy 是主选择组；默认选 日美节点。",
        "# 韩国节点 / 港澳节点 / 10x+节点 只是备用，需要时在 Shadowrocket 里手动切换。",
        "Proxy = select,日美节点,美国节点,日本节点,韩国节点,港澳节点,10x+节点,DIRECT",
        "",
        "# 其他国外代理默认走这里：只匹配美国/日本真实节点，并排除 high_regex 命中的高倍率节点。",
        f"日美节点 = url-test,policy-regex-filter={us_jp_filter},url={TEST_URL},interval=300,tolerance=80",
        f"美国节点 = url-test,policy-regex-filter={us_filter},url={TEST_URL},interval=300,tolerance=80",
        f"日本节点 = url-test,policy-regex-filter={jp_filter},url={TEST_URL},interval=300,tolerance=80",
        "",
        "# 备用组：默认规则不会走，手动切换 Proxy 时使用。",
        f"韩国节点 = url-test,policy-regex-filter={kr_filter},url={TEST_URL},interval=300,tolerance=80",
        f"港澳节点 = url-test,policy-regex-filter={hkmac_filter},url={TEST_URL},interval=300,tolerance=80",
        f"10x+节点 = select,policy-regex-filter=(?i)({high_regex})",
        "",
    ]


def build_output(
    source_text: str,
    source_url: str,
    final_policy: str,
    high_regex: str,
    drop_reject: bool,
    keep_general: bool,
) -> str:
    sections = split_sections(source_text)

    if not sections.rules:
        raise ValueError("No [Rule] section found in source file.")

    out: List[str] = [
        "# Shadowrocket custom config generated from Johnshall rules",
        f"# Source: {source_url}",
        "# Custom routing:",
        "#   OpenAI / ChatGPT / Codex / iOS ChatGPT App -> 美国节点",
        "#   Anthropic / Claude -> 美国节点",
        "#   Source Proxy / PROXY rules -> 日美节点",
        "#   DIRECT remains DIRECT",
        "#   REJECT remains REJECT unless --drop-reject is used",
        "",
    ]

    if keep_general and sections.general:
        out.append("[General]")
        out.extend(sections.general)
        out.append("")
    else:
        out.extend(
            [
                "[General]",
                "ipv6 = false",
                "bypass-system = true",
                "skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, fe80::/10, fc00::/7, localhost, *.local, *.lan",
                "bypass-tun = 10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16",
                "dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query",
                "",
            ]
        )

    out.extend(build_proxy_groups(high_regex=high_regex))

    out.append("[Rule]")
    out.extend(convert_rules(sections.rules, final_policy=final_policy, drop_reject=drop_reject))
    out.append("")

    return "\n".join(out)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a Shadowrocket .conf from Johnshall rules with US/JP default routing."
    )
    parser.add_argument(
        "--source-url",
        default=DEFAULT_SOURCE_URL,
        help=f"Johnshall Shadowrocket .conf URL. Default: {DEFAULT_SOURCE_URL}",
    )
    parser.add_argument(
        "--output",
        default="Shadowrocket_USJP_Custom.conf",
        help="Output Shadowrocket .conf path.",
    )
    parser.add_argument(
        "--final-policy",
        default="日美节点",
        help="Policy for FINAL rule. Default: 日美节点",
    )
    parser.add_argument(
        "--high-regex",
        default=DEFAULT_HIGH_REGEX,
        help=(
            "Regex for high-rate nodes. Used to exclude >=10x nodes from low-rate region groups "
            "and to build 10x+节点. Default strictly matches 10x and above, including 10x, 10.5x, 20x, 100x."
        ),
    )
    parser.add_argument(
        "--drop-reject",
        action="store_true",
        help="Drop REJECT rules if using an ad-heavy source.",
    )
    parser.add_argument(
        "--no-keep-general",
        action="store_true",
        help="Do not copy [General] from source; use a minimal built-in [General].",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    try:
        source_text = download_text(args.source_url)
        output_text = build_output(
            source_text=source_text,
            source_url=args.source_url,
            final_policy=args.final_policy,
            high_regex=args.high_regex,
            drop_reject=args.drop_reject,
            keep_general=not args.no_keep_general,
        )
        output_path = Path(args.output)
        output_path.write_text(output_text, encoding="utf-8")
        print(f"Generated: {output_path.resolve()}")
        print("Import this .conf into Shadowrocket, not Nextin.")
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
