#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DoH 解析工具 —— 本机 DNS 会把部分靶标域名投毒成 240e:45::8888（连不上），
用这个脚本走公共 DoH 拿真实 IP，再配合 curl --resolve 访问，不改系统 DNS。

用法:
    python runs/tools/doh.py www.<客户域名>
    python runs/tools/doh.py www.<客户域名> --curl   # 直接给出 --resolve 参数
    python runs/tools/doh.py a.com b.com c.com --json

退出码: 0=至少一个域名解析成功；1=全部失败
"""
import io
import json
import sys
import urllib.request

ENDPOINTS = [
    "https://dns.alidns.com/resolve",   # 阿里 DoH，国内稳定
    "https://doh.pub/dns-query",        # 腾讯 DoH，备用
]


def doh(name, qtype):
    """返回 (records, status)。records 为 A/AAAA 的 data 列表。"""
    for ep in ENDPOINTS:
        try:
            req = urllib.request.Request(
                "%s?name=%s&type=%s" % (ep, name, qtype),
                headers={"accept": "application/dns-json"},
            )
            with urllib.request.urlopen(req, timeout=15) as f:
                d = json.load(f)
            status = d.get("Status")
            ans = [a["data"] for a in (d.get("Answer") or [])
                   if a.get("type") in (1, 5, 28) and a.get("data")]
            if status == 0 and ans:
                return ans, status
            if status is not None and status != 0:
                return [], status
        except Exception:
            continue
    return [], None


STATUS_MEANING = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN（域名不存在）", 5: "REFUSED"}


def resolve(name):
    a, st_a = doh(name, "A")
    aaaa, st_aaaa = doh(name, "AAAA")
    cname, _ = doh(name, "CNAME")
    st = st_a if st_a not in (None, 0) else st_aaaa
    return {"name": name, "a": a, "aaaa": aaaa, "cname": cname,
            "status": st, "status_meaning": STATUS_MEANING.get(st, st)}


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    as_curl = "--curl" in sys.argv
    if not args:
        print(__doc__)
        return 2

    results = [resolve(d) for d in args]
    ok = 0
    if as_json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        for r in results:
            ips = r["a"] or r["aaaa"]
            if ips:
                ok += 1
                print("%-28s %s%s" % (r["name"], ", ".join(ips),
                                      "  (CNAME %s)" % r["cname"][0] if r["cname"] else ""))
            else:
                print("%-28s ❌ %s" % (r["name"], r["status_meaning"] or "无记录（DoH 未返回结果）"))
            if as_curl and ips:
                for ip in ips:
                    if ":" in ip:
                        print('   curl -k --resolve "%s:443:[%s]" "https://%s/"' % (r["name"], ip, r["name"]))
                    else:
                        print('   curl -k --resolve "%s:443:%s" "https://%s/"' % (r["name"], ip, r["name"]))
        print()
        print("提示：本机 DNS 若把域名解析成 240e:45::8888 或 0.0.0.0，说明被投毒/屏蔽，")
        print("      请用上面 --curl 给出的 --resolve 方式访问，不要去改系统 DNS。")
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
