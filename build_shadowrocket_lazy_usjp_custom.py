#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build a lightweight but functional Shadowrocket .conf from Johnshall lazy.conf.

This version is tuned for the user's requirements:
  - Keep Shadowrocket native .conf format.
  - Use lazy.conf as the base rule source, not the huge sr_top500_banlist_ad.conf.
  - Use a minimal, stable [General] by default:
      ipv6 = false
      no lazy.conf aggressive DNS fallback behavior
      no MITM / URL Rewrite copied by default
  - OpenAI / ChatGPT / Codex / iOS ChatGPT App -> 美国节点
  - Anthropic / Claude -> 美国节点
  - Twitter / X / Instagram / Facebook/Meta CDN -> 日美节点 with explicit fallback domains
  - lazy.conf PROXY rules -> 日美节点
  - lazy.conf DIRECT rules -> DIRECT
  - FINAL,PROXY -> FINAL,日美节点
  - 韩国节点 / 港澳节点 / 10x+节点 only as manual backup groups.
  - Strict high-rate matching: >=10x by default.

Usage:
  python3 build_shadowrocket_lazy_usjp_custom_v4.py \
    --output Shadowrocket_Lazy_USJP_Custom.conf

Optional:
  # Keep lazy.conf General instead of minimal General
  python3 build_shadowrocket_lazy_usjp_custom_v4.py --keep-lazy-general \
    --output Shadowrocket_Lazy_USJP_Custom.conf

  # Copy lazy.conf Host / URL Rewrite / MITM sections too
  python3 build_shadowrocket_lazy_usjp_custom_v4.py --include-extra-sections \
    --output Shadowrocket_Lazy_USJP_Custom.conf
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


DEFAULT_SOURCE_URL = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/lazy.conf"
DEFAULT_TEST_URL = "http://www.gstatic.com/generate_204"

# Strict >=10x matching.
# Matches: 10x, 10.5x, 11x, 20x, 100x
# Does not match: 1x, 2x, 5x, 5.5x, 6x, 9x
DEFAULT_HIGH_REGEX = r"([1-9][0-9]+(\.[0-9]+)? *[xX])"


OPENAI_RULES = [
    "# ===== OpenAI / ChatGPT / Codex / iOS ChatGPT App -> 美国节点 =====",
    "RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/OpenAI/OpenAI.list,美国节点",
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
    "RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Anthropic/Anthropic.list,美国节点",
    "DOMAIN-SUFFIX,anthropic.com,美国节点",
    "DOMAIN-SUFFIX,anthropicusercontent.com,美国节点",
    "DOMAIN-SUFFIX,claude.ai,美国节点",
    "DOMAIN-SUFFIX,claude.com,美国节点",
    "",
]

SOCIAL_RULES = [
    "# ===== Twitter / X / Instagram / Meta CDN -> 日美节点 =====",
    # Rule sets first. If a RULE-SET fails to load, the explicit fallback domains below still work.
    "RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Twitter/Twitter.list,日美节点",
    "RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Instagram/Instagram.list,日美节点",
    "RULE-SET,https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Facebook/Facebook.list,日美节点",
    "",
    "# Twitter / X explicit fallback",
    "DOMAIN-SUFFIX,x.com,日美节点",
    "DOMAIN-SUFFIX,api.x.com,日美节点",
    "DOMAIN-SUFFIX,twitter.com,日美节点",
    "DOMAIN-SUFFIX,api.twitter.com,日美节点",
    "DOMAIN-SUFFIX,mobile.twitter.com,日美节点",
    "DOMAIN-SUFFIX,t.co,日美节点",
    "DOMAIN-SUFFIX,twimg.com,日美节点",
    "DOMAIN-SUFFIX,twimg.co,日美节点",
    "DOMAIN-SUFFIX,twimg.org,日美节点",
    "DOMAIN-SUFFIX,twtrdns.net,日美节点",
    "DOMAIN-SUFFIX,twttr.com,日美节点",
    "DOMAIN-SUFFIX,twttr.net,日美节点",
    "DOMAIN-SUFFIX,pscp.tv,日美节点",
    "DOMAIN-SUFFIX,periscope.tv,日美节点",
    "DOMAIN-KEYWORD,twitter,日美节点",
    "",
    "# Instagram / Facebook / Meta explicit fallback",
    "DOMAIN-SUFFIX,instagram.com,日美节点",
    "DOMAIN-SUFFIX,www.instagram.com,日美节点",
    "DOMAIN-SUFFIX,i.instagram.com,日美节点",
    "DOMAIN-SUFFIX,graph.instagram.com,日美节点",
    "DOMAIN-SUFFIX,cdninstagram.com,日美节点",
    "DOMAIN-SUFFIX,instagr.am,日美节点",
    "DOMAIN-SUFFIX,facebook.com,日美节点",
    "DOMAIN-SUFFIX,facebook.net,日美节点",
    "DOMAIN-SUFFIX,fb.com,日美节点",
    "DOMAIN-SUFFIX,fbcdn.net,日美节点",
    "DOMAIN-SUFFIX,fbsbx.com,日美节点",
    "DOMAIN-SUFFIX,connect.facebook.net,日美节点",
    "DOMAIN-SUFFIX,graph.facebook.com,日美节点",
    "DOMAIN-SUFFIX,static.xx.fbcdn.net,日美节点",
    "DOMAIN-SUFFIX,meta.com,日美节点",
    "DOMAIN-SUFFIX,messenger.com,日美节点",
    "DOMAIN-KEYWORD,instagram,日美节点",
    "DOMAIN-KEYWORD,facebook,日美节点",
    "",
]


def download_text(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 shadowrocket-lazy-usjp-v4/1.0",
            "Accept": "text/plain,*/*",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def read_source(source_url: str, source_file: Optional[str]) -> Tuple[str, str]:
    if source_file:
        p = Path(source_file)
        return p.read_text(encoding="utf-8"), str(p)
    return download_text(source_url), source_url


def split_sections(text: str) -> Dict[str, List[str]]:
    sections: Dict[str, List[str]] = {}
    current: Optional[str] = None

    for raw in text.splitlines():
        line = raw.rstrip("\r\n")
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections.setdefault(current, []).append(line)

    return sections


def strip_inline_comment(line: str) -> Tuple[str, str]:
    m = re.search(r"\s+#", line)
    if not m:
        return line.rstrip(), ""
    return line[:m.start()].rstrip(), line[m.start():].rstrip()


def normalize_policy(policy: str) -> str:
    p = policy.strip()
    lower = p.lower()

    if lower == "proxy":
        return "日美节点"
    if lower == "direct":
        return "DIRECT"
    if lower == "reject":
        return "REJECT"
    if lower.startswith("reject-"):
        return p.upper()

    # Keep other policies if source has them.
    return p


def is_rule_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    kind = stripped.split(",", 1)[0].upper()
    return kind in {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "DOMAIN-WILDCARD",
        "USER-AGENT",
        "URL-REGEX",
        "IP-CIDR",
        "IP-ASN",
        "RULE-SET",
        "DOMAIN-SET",
        "SCRIPT",
        "DST-PORT",
        "GEOIP",
        "FINAL",
        "AND",
        "NOT",
        "OR",
        "PROTOCOL",
    }


def convert_rule_line(line: str, final_policy: str, drop_reject: bool) -> Optional[str]:
    stripped = line.strip()

    if not stripped or stripped.startswith("#"):
        return line.rstrip()

    rule_part, comment = strip_inline_comment(line)
    if not rule_part:
        return line.rstrip()

    fields = [x.strip() for x in rule_part.split(",")]
    if not fields:
        return line.rstrip()

    if fields[0].upper() == "FINAL":
        return f"FINAL,{final_policy}" + (f" {comment}" if comment else "")

    # IP-CIDR,...,Policy,no-resolve
    policy_i = len(fields) - 1
    if fields[-1].lower() == "no-resolve" and len(fields) >= 3:
        policy_i = len(fields) - 2

    new_policy = normalize_policy(fields[policy_i])
    if drop_reject and new_policy.upper().startswith("REJECT"):
        return None

    fields[policy_i] = new_policy
    return ",".join(fields) + (f" {comment}" if comment else "")


def convert_rules(lazy_rules: Iterable[str], final_policy: str, drop_reject: bool) -> List[str]:
    out: List[str] = []
    out.extend(OPENAI_RULES)
    out.extend(ANTHROPIC_RULES)
    out.extend(SOCIAL_RULES)
    out.append("# ===== lazy.conf rules, with PROXY mapped to 日美节点 =====")

    seen_final = False
    for line in lazy_rules:
        converted = convert_rule_line(line, final_policy, drop_reject)
        if converted is None:
            continue
        if converted.strip().upper().startswith("FINAL,"):
            seen_final = True
        out.append(converted)

    if not seen_final:
        out.append("")
        out.append(f"FINAL,{final_policy}")

    return out


def negative_filter(region: str, high: str) -> str:
    # Require region keyword and exclude 10x+ high-rate keyword.
    # Shadowrocket supports lookahead syntax in policy-regex-filter.
    return f"(?i)^(?=.*({region}))(?!.*({high})).*$"


def build_proxy_groups(high: str, test_url: str) -> List[str]:
    # Keep filters broad enough for common airport naming.
    us = r"🇺🇸|美国|美國|United States|America|洛杉矶|西雅图|芝加哥|纽约|US|USA"
    jp = r"🇯🇵|日本|Japan|Tokyo|Osaka|东京|大阪|JP|JPN"
    kr = r"🇰🇷|韩国|韓國|Korea|首尔|春川|KR|KOR"
    hkmac = r"🇭🇰|香港|Hong Kong|HK|HKG|澳门|澳門|Macao|Macau|MO"

    return [
        "[Proxy Group]",
        "# 主选择组：默认选 日美节点；韩国 / 港澳 / 10x+ 只作为手动备用。",
        "Proxy = select,日美节点,美国节点,日本节点,韩国节点,港澳节点,10x+节点,DIRECT,policy-select-name=日美节点",
        "",
        "# 默认国外流量：只匹配美国/日本真实节点，并排除 10x+ 高倍率。",
        f"日美节点 = url-test,policy-regex-filter={negative_filter(us + '|' + jp, high)},url={test_url},interval=300,timeout=5,tolerance=80,select=0",
        f"美国节点 = url-test,policy-regex-filter={negative_filter(us, high)},url={test_url},interval=300,timeout=5,tolerance=80,select=0",
        f"日本节点 = url-test,policy-regex-filter={negative_filter(jp, high)},url={test_url},interval=300,timeout=5,tolerance=80,select=0",
        "",
        "# 备用组：规则默认不会走，手动切换 Proxy 时使用。",
        f"韩国节点 = url-test,policy-regex-filter={negative_filter(kr, high)},url={test_url},interval=300,timeout=5,tolerance=80,select=0",
        f"港澳节点 = url-test,policy-regex-filter={negative_filter(hkmac, high)},url={test_url},interval=300,timeout=5,tolerance=80,select=0",
        f"10x+节点 = select,policy-regex-filter=(?i)({high})",
        "",
    ]


def minimal_general() -> List[str]:
    return [
        "[General]",
        "# 稳定优先：这里不直接使用 lazy.conf 复杂 General，避免 IPv6/DNS/UDP 行为导致 App 异常。",
        "ipv6 = false",
        "prefer-ipv6 = false",
        "bypass-system = true",
        "skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,captive.apple.com",
        "tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16",
        "dns-server = https://doh.pub/dns-query,https://dns.alidns.com/dns-query,223.5.5.5,119.29.29.29",
        "fallback-dns-server = system",
        "dns-direct-system = false",
        "private-ip-answer = true",
        "dns-direct-fallback-proxy = false",
        "icmp-auto-reply = true",
        "block-quic = all-proxy",
        "udp-policy-not-supported-behaviour = REJECT",
        "",
    ]


def general_from_lazy(lines: List[str]) -> List[str]:
    return ["[General]"] + lines + [""]


def build_output(
    source_text: str,
    source_name: str,
    final_policy: str,
    high_regex: str,
    test_url: str,
    drop_reject: bool,
    keep_lazy_general: bool,
    include_extra_sections: bool,
) -> str:
    sections = split_sections(source_text)
    lazy_rules = sections.get("[Rule]", [])
    if not lazy_rules:
        raise ValueError("No [Rule] section found in source file.")

    out: List[str] = [
        "# Shadowrocket custom config generated from Johnshall lazy.conf",
        f"# Source: {source_name}",
        "# Custom routing:",
        "#   OpenAI / ChatGPT / Codex / iOS ChatGPT App -> 美国节点",
        "#   Anthropic / Claude -> 美国节点",
        "#   Twitter / X / Instagram / Meta CDN -> 日美节点",
        "#   lazy.conf PROXY rules -> 日美节点",
        "#   DIRECT remains DIRECT",
        "#   FINAL,PROXY -> FINAL,日美节点",
        "",
    ]

    if keep_lazy_general:
        out.extend(general_from_lazy(sections.get("[General]", [])))
    else:
        out.extend(minimal_general())

    out.extend(build_proxy_groups(high_regex, test_url))
    out.append("[Rule]")
    out.extend(convert_rules(lazy_rules, final_policy, drop_reject))

    if include_extra_sections:
        for name in ("[Host]", "[URL Rewrite]", "[MITM]"):
            if name in sections:
                out.append("")
                out.append(name)
                out.extend(sections[name])

    out.append("")
    return "\n".join(out)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build a working lightweight Shadowrocket config from Johnshall lazy.conf."
    )
    p.add_argument("--source-url", default=DEFAULT_SOURCE_URL)
    p.add_argument("--source-file", default=None)
    p.add_argument("--output", default="Shadowrocket_Lazy_USJP_Custom.conf")
    p.add_argument("--final-policy", default="日美节点")
    p.add_argument("--high-regex", default=DEFAULT_HIGH_REGEX)
    p.add_argument("--test-url", default=DEFAULT_TEST_URL)
    p.add_argument("--drop-reject", action="store_true")
    p.add_argument("--keep-lazy-general", action="store_true", help="Use lazy.conf [General] instead of stable minimal [General]")
    p.add_argument("--include-extra-sections", action="store_true", help="Copy [Host], [URL Rewrite], [MITM] from lazy.conf")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        text, source_name = read_source(args.source_url, args.source_file)
        output = build_output(
            source_text=text,
            source_name=source_name,
            final_policy=args.final_policy,
            high_regex=args.high_regex,
            test_url=args.test_url,
            drop_reject=args.drop_reject,
            keep_lazy_general=args.keep_lazy_general,
            include_extra_sections=args.include_extra_sections,
        )
        out_path = Path(args.output)
        out_path.write_text(output, encoding="utf-8")
        print(f"Generated: {out_path.resolve()}")
        print("Import this .conf into Shadowrocket and set Global Routing to Config.")
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
