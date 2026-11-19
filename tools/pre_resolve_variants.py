#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""靶标主机名变体预解析（只做 DoH 查询，不发任何目标请求）。

为什么需要：本机 DNS 会把部分靶标域名投毒成 240e:45::8888，队友直接 curl 会全部失败。
先在这里用公共 DoH 把「主域 + 常见业务前缀」解析出来，队友拿 IP 用 curl --resolve 即可。

用法:
    python runs/tools/pre_resolve_variants.py            # 用内置 BATTERY 跑 6 个靶标
    python runs/tools/pre_resolve_variants.py --json out.json --md out.md

关键点：先测通配符（随机标签）。若泛解析，所有子域都会"解析成功"，必须标记出来，
否则会把泛解析当成真实资产（这是 vhost/子域枚举最常见的假阳性来源）。
"""
import argparse
import io
import json
import random
import string
import sys
import time
import urllib.request

ENDPOINTS = ["https://dns.alidns.com/resolve", "https://doh.pub/dns-query"]

BATTERY = [
    # (单位, 台账行, 主域, 类型)
    ("某省级医院",   "R16", "<客户域名>",             "hospital"),
    ("某中医院", "R17", "hnzyfy.com",           "hospital"),
    ("某大学附属医院",      "R18", "<客户域名>",          "hospital"),
    ("某工科高校",         "R19", "<客户域名>",          "university"),
    ("某高校",         "R20", "haust.edu.cn",          "university"),
    ("某研究型高校",         "R21", "<客户域名>",   "university"),
]

UNI_PREFIXES = ["www", "oa", "jw", "jwc", "jwxt", "ecard", "lib", "vpn", "webvpn",
                "idp", "cas", "sso", "auth", "mail", "portal", "ehall", "my", "yjs",
                "job", "cwc", "rsc", "xsc", "nic", "net", "api", "m", "wap", "bbs", "news"]

HOS_PREFIXES = ["www", "oa", "his", "lis", "pacs", "yygh", "gh", "report", "bgcx",
                "tj", "tjzx", "web", "mail", "hr", "cw", "zbcg", "api", "m", "wap",
                "doctor", "yq", "portal", "app", "user", "member"]


def doh(name, qtype, retry=2):
    for attempt in range(retry + 1):
        for ep in ENDPOINTS:
            try:
                req = urllib.request.Request(
                    "%s?name=%s&type=%s" % (ep, name, qtype),
                    headers={"accept": "application/dns-json"})
                with urllib.request.urlopen(req, timeout=12) as f:
                    d = json.load(f)
                st = d.get("Status")
                ans = [a["data"] for a in (d.get("Answer") or [])
                       if a.get("type") == (1 if qtype == "A" else 28)]
                if st == 0:
                    return ans, 0
                if st == 3:
                    return [], 3
            except Exception:
                continue
        time.sleep(0.3 * (attempt + 1))
    return [], None


def random_label(n=12):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def probe_wildcard(base):
    label = "%s.%s" % (random_label(), base)
    a, st = doh(label, "A")
    return {"probe": label, "status": st, "ips": a}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default="runs/notes/hostname-variants.json")
    ap.add_argument("--md", default="runs/notes/六靶标主机名变体预解析.md")
    ap.add_argument("--delay", type=float, default=0.15)
    a = ap.parse_args()

    results = []
    for unit, row, base, kind in BATTERY:
        prefixes = UNI_PREFIXES if kind == "university" else HOS_PREFIXES
        print("\n=== %s（%s）%s ===" % (unit, row, base))
        wc = probe_wildcard(base)
        wc_hit = bool(wc["ips"])
        print("  通配符探测: %s -> %s %s" % (
            wc["probe"], wc["ips"] or "NXDOMAIN/无",
            "⚠️ 泛解析！所有前缀都会'解析成功'，必须按 IP 去重否证" if wc_hit else "✅ 无泛解析"))

        entry = {"unit": unit, "row": row, "base": base, "kind": kind,
                 "wildcard": wc, "records": []}

        names = [base] + ["%s.%s" % (p, base) for p in prefixes]
        seen_ips = {}
        for n in names:
            a_ips, st = doh(n, "A")
            if a_ips:
                aaaa, _ = doh(n, "AAAA") if n == base or not wc_hit else ([], 0)
                entry["records"].append({"name": n, "a": a_ips, "aaaa": aaaa, "status": st})
                for ip in a_ips:
                    seen_ips.setdefault(ip, []).append(n)
                print("  ✅ %-34s %s" % (n, ", ".join(a_ips)))
            else:
                entry["records"].append({"name": n, "a": [], "aaaa": [], "status": st})
            time.sleep(a.delay)

        entry["distinct_ips"] = {ip: hosts for ip, hosts in seen_ips.items()}
        if wc_hit:
            wc_ips = set(wc["ips"])
            real = {ip: h for ip, h in seen_ips.items() if ip not in wc_ips}
            entry["non_wildcard_ips"] = real
            print("  → 泛解析 IP: %s ；去掉泛解析后真实 IP 组: %d 组" % (
                ", ".join(wc_ips), len(real)))
        results.append(entry)

    # 写 JSON
    io.open(a.json, "w", encoding="utf-8", newline="\n").write(
        json.dumps(results, ensure_ascii=False, indent=2) + "\n")

    # 写 Markdown
    lines = ["# 六靶标主机名变体预解析（DoH，仅 DNS 查询）", "",
             "> 生成时间：%s" % time.strftime("%Y-%m-%d %H:%M"),
             "> 本机 DNS 会把这批域名投毒为 `240e:45::8888`，本表用公共 DoH（阿里/腾讯）解析。",
             "> 用法：`curl -k --resolve \"<域名>:443:<IP>\" \"https://<域名>/\"`", ""]
    for e in results:
        lines.append("## %s ｜%s ｜`%s`" % (e["unit"], e["row"], e["base"]))
        wc = e["wildcard"]
        lines.append("")
        lines.append("- 通配符探测：`%s` → %s %s" % (
            wc["probe"], ", ".join(wc["ips"]) if wc["ips"] else "无记录",
            "⚠️ **存在泛解析**" if wc["ips"] else "✅ 无泛解析"))
        hits = [r for r in e["records"] if r["a"]]
        lines.append("- 解析成功：**%d / %d**" % (len(hits), len(e["records"])))
        if hits:
            lines.append("")
            lines.append("| 主机名 | IPv4 | IPv6 |")
            lines.append("|---|---|---|")
            for r in hits:
                lines.append("| `%s` | %s | %s |" % (
                    r["name"], ", ".join(r["a"]) or "-", ", ".join(r["aaaa"]) or "-"))
        if wc["ips"] and e.get("non_wildcard_ips") is not None:
            lines.append("")
            lines.append("- **去掉泛解析 IP 后仍存在的**：%s" % (
                ", ".join("%s(%s)" % (ip, ",".join(h)) for ip, h in e["non_wildcard_ips"].items())
                or "无（全部疑似泛解析）"))
        lines.append("")
    io.open(a.md, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")
    print("\n写出:\n  %s\n  %s" % (a.json, a.md))
    return 0


if __name__ == "__main__":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
