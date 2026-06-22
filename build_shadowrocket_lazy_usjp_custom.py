#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build a Shadowrocket .conf using Johnshall lazy.conf rules, but keep your custom routing groups.

Default source:
  https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/lazy.conf

Output format:
  Shadowrocket .conf
  NOT Clash / Mihomo / Nextin YAML.

Custom routing:
  - OpenAI / ChatGPT / Codex / iOS ChatGPT App -> 美国节点, with BlackMatrix7 OpenAI RULE-SET
  - Anthropic / Claude -> 美国节点, with BlackMatrix7 Anthropic RULE-SET
  - lazy.conf rules with PROXY / Proxy -> 日美节点
  - lazy.conf rules with DIRECT -> DIRECT
  - lazy.conf rules with REJECT variants -> keep as-is
  - FINAL,PROXY -> FINAL,日美节点

Proxy groups generated:
  Proxy
  日美节点
  美国节点
  日本节点
  韩国节点
  港澳节点
  10x+节点

High-rate matching:
  Strictly matches >=10x by default:
  10x, 10.5x, 11x, 20x, 100x...
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
DEFAULT_HIGH_REGEX = r"(?:1[0-9]|[2-9][0-9]|[1-9][0-9]{2,})(?:\.\d+)?\s*x"


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


def download_text(url: str, timeout: int = 30) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 shadowrocket-lazy-custom-builder/1.0",
            "Accept": "text/plain,*/*",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8")


def read_source(source_url: Optional[str], source_file: Optional[str]) -> Tuple[str, str]:
    if source_file:
        path = Path(source_file)
        return path.read_text(encoding="utf-8"), str(path)
    if not source_url:
        source_url = DEFAULT_SOURCE_URL
    return download_text(source_url), source_url


def split_sections(text: str) -> Dict[str, List[str]]:
    sections: Dict[str, List[str]] = {}
    current: Optional[str] = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()

        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped
            sections.setdefault(current, [])
            continue

        if current is not None:
            sections.setdefault(current, []).append(line)

    return sections


def strip_inline_comment(line: str) -> Tuple[str, str]:
    """
    Split inline comments conservatively.
    Only treats whitespace + # as the beginning of a comment.
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
    if lower == "reject":
        return "REJECT"

    # Keep Shadowrocket specialized reject actions.
    if lower.startswith("reject-"):
        return p.upper()

    return p


def convert_rule_line(line: str, final_policy: str, drop_reject: bool) -> Optional[str]:
    stripped = line.strip()

    if not stripped or stripped.startswith("#"):
        return line.rstrip()

    rule_part, comment = strip_inline_comment(line)
    if not rule_part:
        return line.rstrip()

    fields = [field.strip() for field in rule_part.split(",")]
    if not fields:
        return line.rstrip()

    rule_type = fields[0].upper()

    if rule_type == "FINAL":
        return f"FINAL,{final_policy}" + (f" {comment}" if comment else "")

    # IP-CIDR,...,Policy,no-resolve
    policy_idx = len(fields) - 1
    if fields[-1].lower() == "no-resolve" and len(fields) >= 3:
        policy_idx = len(fields) - 2

    old_policy = fields[policy_idx]
    new_policy = normalize_policy(old_policy)

    if drop_reject and new_policy.upper().startswith("REJECT"):
        return None

    fields[policy_idx] = new_policy
    return ",".join(fields) + (f" {comment}" if comment else "")


def is_rule_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False
    first = stripped.split(",", 1)[0].upper()
    return first in {
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


def convert_rules(lazy_rules: Iterable[str], final_policy: str, drop_reject: bool) -> List[str]:
    converted: List[str] = []
    converted.extend(OPENAI_RULES)
    converted.extend(ANTHROPIC_RULES)
    converted.append("# ===== lazy.conf rules, with PROXY mapped to 日美节点 =====")

    seen_final = False

    for line in lazy_rules:
        out = convert_rule_line(line, final_policy=final_policy, drop_reject=drop_reject)
        if out is None:
            continue
        if is_rule_line(out) and out.strip().upper().startswith("FINAL,"):
            seen_final = True
        converted.append(out)

    if not seen_final:
        converted.append("")
        converted.append(f"FINAL,{final_policy}")

    return converted


def negative_filter(region_regex: str, high_regex: str) -> str:
    # Shadowrocket policy-regex-filter: require region keyword and exclude high-rate keyword.
    return f"(?i)^(?=.*({region_regex}))(?!.*({high_regex})).*$"


def build_proxy_groups(high_regex: str, test_url: str) -> List[str]:
    us = r"🇺🇸|美国|美國|United States|America|洛杉矶|西雅图|芝加哥|纽约|\bUS\b|\bUSA\b"
    jp = r"🇯🇵|日本|Japan|Tokyo|Osaka|东京|大阪|\bJP\b|JPN"
    kr = r"🇰🇷|韩国|韓國|Korea|首尔|春川|\bKR\b|KOR"
    hkmac = r"🇭🇰|香港|Hong Kong|\bHK\b|HKG|澳门|澳門|Macao|Macau|\bMO\b"

    us_jp_filter = negative_filter(f"{us}|{jp}", high_regex)
    us_filter = negative_filter(us, high_regex)
    jp_filter = negative_filter(jp, high_regex)
    kr_filter = negative_filter(kr, high_regex)
    hkmac_filter = negative_filter(hkmac, high_regex)

    return [
        "[Proxy Group]",
        "# 主选择组：默认选 日美节点；韩国 / 港澳 / 10x+ 只作为手动备用。",
        "Proxy = select,日美节点,美国节点,日本节点,韩国节点,港澳节点,10x+节点,DIRECT,policy-select-name=日美节点",
        "",
        "# 默认国外流量：只匹配美国/日本真实节点，并排除 10x+ 高倍率。",
        f"日美节点 = url-test,policy-regex-filter={us_jp_filter},url={test_url},interval=300,timeout=5,tolerance=80,select=0",
        f"美国节点 = url-test,policy-regex-filter={us_filter},url={test_url},interval=300,timeout=5,tolerance=80,select=0",
        f"日本节点 = url-test,policy-regex-filter={jp_filter},url={test_url},interval=300,timeout=5,tolerance=80,select=0",
        "",
        "# 备用组：规则默认不会走，手动切换 Proxy 时使用。",
        f"韩国节点 = url-test,policy-regex-filter={kr_filter},url={test_url},interval=300,timeout=5,tolerance=80,select=0",
        f"港澳节点 = url-test,policy-regex-filter={hkmac_filter},url={test_url},interval=300,timeout=5,tolerance=80,select=0",
        f"10x+节点 = select,policy-regex-filter=(?i)({high_regex})",
        "",
    ]


def default_general_from_lazy(lazy_general: List[str]) -> List[str]:
    """
    Keep lazy.conf General by default because it is Shadowrocket-native and contains useful DNS/TUN notes.
    You can use --minimal-general if you want a smaller General section.
    """
    return ["[General]"] + lazy_general + [""]


def minimal_general() -> List[str]:
    return [
        "[General]",
        "ipv6 = false",
        "bypass-system = true",
        "skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,captive.apple.com",
        "tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16",
        "dns-server = https://doh.pub/dns-query,https://dns.alidns.com/dns-query,223.5.5.5,119.29.29.29",
        "fallback-dns-server = system",
        "private-ip-answer = true",
        "block-quic = all-proxy",
        "",
    ]


def build_output(
    source_text: str,
    source_name: str,
    final_policy: str,
    high_regex: str,
    test_url: str,
    drop_reject: bool,
    minimal_general_enabled: bool,
) -> str:
    sections = split_sections(source_text)

    general = sections.get("[General]", [])
    rules = sections.get("[Rule]", [])

    if not rules:
        raise ValueError("No [Rule] section found in source lazy.conf")

    out: List[str] = [
        "# Shadowrocket custom config generated from Johnshall lazy.conf",
        f"# Source: {source_name}",
        "# Custom routing:",
        "#   OpenAI / ChatGPT / Codex / iOS ChatGPT App -> 美国节点, with BlackMatrix7 OpenAI RULE-SET",
        "#   Anthropic / Claude -> 美国节点, with BlackMatrix7 Anthropic RULE-SET",
        "#   lazy.conf PROXY rules -> 日美节点",
        "#   DIRECT remains DIRECT",
        "#   FINAL,PROXY -> FINAL,日美节点",
        "",
    ]

    out.extend(minimal_general() if minimal_general_enabled else default_general_from_lazy(general))
    out.extend(build_proxy_groups(high_regex=high_regex, test_url=test_url))
    out.append("[Rule]")
    out.extend(convert_rules(rules, final_policy=final_policy, drop_reject=drop_reject))

    # Keep Host / URL Rewrite / MITM from lazy.conf. They are Shadowrocket-native and useful.
    # But do not keep the [Proxy] section because your nodes come from subscription/import.
    for section_name in ("[Host]", "[URL Rewrite]", "[MITM]"):
        content = sections.get(section_name)
        if content is not None:
            out.append("")
            out.append(section_name)
            out.extend(content)

    out.append("")
    return "\n".join(out)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a Shadowrocket .conf from Johnshall lazy.conf with custom US/JP routing."
    )
    parser.add_argument("--source-url", default=DEFAULT_SOURCE_URL, help="lazy.conf URL")
    parser.add_argument("--source-file", default=None, help="Use a local lazy.conf instead of downloading")
    parser.add_argument("--output", default="Shadowrocket_Lazy_USJP_Custom.conf", help="Output .conf path")
    parser.add_argument("--final-policy", default="日美节点", help="Policy for FINAL rule")
    parser.add_argument("--high-regex", default=DEFAULT_HIGH_REGEX, help="Regex matching >=10x high-rate nodes")
    parser.add_argument("--test-url", default=DEFAULT_TEST_URL, help="URL used by url-test groups")
    parser.add_argument("--drop-reject", action="store_true", help="Drop REJECT rules, if source contains them")
    parser.add_argument("--minimal-general", action="store_true", help="Use smaller General section instead of lazy.conf General")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    try:
        source_text, source_name = read_source(args.source_url, args.source_file)
        output = build_output(
            source_text=source_text,
            source_name=source_name,
            final_policy=args.final_policy,
            high_regex=args.high_regex,
            test_url=args.test_url,
            drop_reject=args.drop_reject,
            minimal_general_enabled=args.minimal_general,
        )
        output_path = Path(args.output)
        output_path.write_text(output, encoding="utf-8")
        print(f"Generated: {output_path.resolve()}")
        print("Import this file into Shadowrocket.")
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
