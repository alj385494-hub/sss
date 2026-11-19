#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""红队库对账工具（只读）——用来核子智能体的回报是否真的落库。

背景（2026-11-14 用户要求）：多智能体协作最大的坑是「回报说做了、库里没有」，
以及「写进别家靶标库」。这个脚本直接读 ~/.dsh/redteam/engagements/<单位>/assets.db，
把每个靶标的落库数量、测试状态分布、收口遗留、证据缺口一次列出来，不给模型解释空间。

用法：
  PY=<HOME>/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/python/python.exe
  "$PY" runs/tools/dbcheck.py --all              # 所有靶标
  "$PY" runs/tools/dbcheck.py 某工科高校 某高校
  "$PY" runs/tools/dbcheck.py --all --json       # 机器可读

设计原则：**只读**（sqlite URI mode=ro），不改任何数据；库不存在就报"未落库"。
"""
import io
import json
import os
import sqlite3
import sys

ROOT = os.path.expanduser("~/.dsh/redteam/engagements")


def open_ro(path):
    uri = "file:%s?mode=ro" % path.replace("\\", "/")
    return sqlite3.connect(uri, uri=True)


def cols(conn, table):
    try:
        return [r[1] for r in conn.execute("PRAGMA table_info(%s)" % table)]
    except sqlite3.Error:
        return []


def count(conn, table, where="", args=()):
    try:
        sql = "SELECT count(*) FROM %s" % table
        if where:
            sql += " WHERE " + where
        return conn.execute(sql, args).fetchone()[0]
    except sqlite3.Error:
        return None


def group(conn, table, col):
    try:
        return dict(conn.execute("SELECT %s, count(*) FROM %s GROUP BY %s" % (col, table, col)))
    except sqlite3.Error:
        return {}


def check_one(name):
    d = os.path.join(ROOT, name)
    db = os.path.join(d, "assets.db")
    out = {"engagement": name, "db_exists": os.path.isfile(db)}
    if not out["db_exists"]:
        out["verdict"] = "未落库（这个靶标一条都没写）"
        return out

    out["db_bytes"] = os.path.getsize(db)
    out["db_mtime"] = __import__("datetime").datetime.fromtimestamp(
        os.path.getmtime(db)).strftime("%Y-%m-%d %H:%M")
    conn = open_ro(db)
    try:
        out["assets"] = count(conn, "asset") or 0
        out["assets_by_state"] = group(conn, "asset", "state")
        out["assets_by_test_status"] = group(conn, "asset", "test_status")
        out["assets_assessed"] = count(conn, "asset", "assessed_at IS NOT NULL") or 0
        out["ports"] = count(conn, "port") or 0
        out["fingerprints"] = count(conn, "fingerprint") or 0
        out["names"] = count(conn, "asset_name") or 0
        out["vulns"] = count(conn, "vuln") or 0
        out["vulns_by_status"] = group(conn, "vuln", "status")
        out["http_evidence"] = count(conn, "http_evidence") or 0
        out["shots"] = count(conn, "shot") or 0
        out["credentials"] = count(conn, "credential") or 0
        out["tunnels"] = count(conn, "tunnel") or 0
        out["tunnels_active"] = count(conn, "tunnel", "status='active'") or 0
        out["webshells"] = count(conn, "webshell") or 0
        out["accesses"] = count(conn, "access_session") or 0
        out["score_hits"] = count(conn, "score_hit") or 0
        out["data_proofs"] = count(conn, "data_proof") or 0
        out["cleanup_open"] = count(conn, "cleanup_item", "status='open'") or 0

        # ---- 告警（都是真实踩过的坑） ----
        warn = []
        if out["vulns"]:
            st = out["vulns_by_status"]
            serious = (st.get("confirmed", 0) or 0) + (st.get("exploited", 0) or 0)
            if serious and out["http_evidence"] == 0:
                warn.append("有 %d 条 confirmed/exploited 但没有一条 HTTP 证据（报告不可复现）" % serious)
        if out["score_hits"] and out["shots"] == 0:
            warn.append("有得分命中但零截图")
        if out["cleanup_open"]:
            warn.append("清理台账还有 %d 项 open（交付前必须处理）" % out["cleanup_open"])
        if out["tunnels_active"]:
            warn.append("还有 %d 条隧道 active（收口时确认是否该关）" % out["tunnels_active"])
        untested = out["assets_by_test_status"].get("untested", 0) or 0
        if out["assets"] and untested == out["assets"]:
            warn.append("资产全部 untested：只落了资产没测（或测试状态没回写）")
        if out["webshells"]:
            broken = count(conn, "webshell", "status IS NOT NULL AND status NOT IN ('online','unknown')") or 0
            if broken:
                warn.append("有 %d 个 WebShell 状态不是 online（已被删/掉线）" % broken)
        out["warnings"] = warn

        # verdict
        if out["assets"] == 0:
            out["verdict"] = "空库（什么都没写）"
        elif out["vulns"] == 0 and out["score_hits"] == 0:
            out["verdict"] = "只有资产，暂无漏洞/得分"
        else:
            out["verdict"] = "有产出"
    finally:
        conn.close()
    return out


def fmt(o):
    if not o["db_exists"]:
        return "== %s ==\n  未落库（没有 assets.db）\n" % o["engagement"]
    L = []
    L.append("== %s ==  db %.1fKB  更新 %s" % (o["engagement"], o["db_bytes"] / 1024.0, o["db_mtime"]))
    st = o["assets_by_state"]
    L.append("  资产 %d（%s）｜端口 %d｜指纹 %d｜名称 %d｜已评估 %d"
             % (o["assets"],
                " ".join("%s=%d" % (k, v) for k, v in sorted(st.items())) or "state 未标",
                o["ports"], o["fingerprints"], o["names"], o["assets_assessed"]))
    ts = o["assets_by_test_status"]
    L.append("  测试状态: %s" % (" ".join("%s=%d" % (k, v) for k, v in sorted(ts.items())) or "全空"))
    vs = o["vulns_by_status"]
    L.append("  漏洞 %d（%s）｜HTTP证据 %d｜截图 %d｜数据证明 %d"
             % (o["vulns"],
                " ".join("%s=%d" % (k, v) for k, v in sorted(vs.items())) or "无",
                o["http_evidence"], o["shots"], o["data_proofs"]))
    L.append("  凭据 %d｜隧道 %d(active %d)｜WebShell %d｜访问会话 %d｜得分命中 %d｜清理 open %d"
             % (o["credentials"], o["tunnels"], o["tunnels_active"], o["webshells"],
                o["accesses"], o["score_hits"], o["cleanup_open"]))
    L.append("  判定: %s" % o["verdict"])
    for w in o["warnings"]:
        L.append("  ⚠ %s" % w)
    return "\n".join(L) + "\n"


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    as_json = "--json" in argv
    if "--all" in argv or not args:
        names = sorted(os.listdir(ROOT)) if os.path.isdir(ROOT) else []
    else:
        names = args
    results = [check_one(n) for n in names]
    if as_json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return 0
    if not results:
        print("没有找到任何靶标库：%s" % ROOT)
        return 1
    for r in results:
        print(fmt(r))
    bad = [r["engagement"] for r in results if r.get("warnings")]
    if bad:
        print("带告警的靶标: %s" % "、".join(bad))
    return 0


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.exit(main(sys.argv))
