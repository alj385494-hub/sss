#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DSH 插件环境基线 / 漂移检查（一次性解决"每次更新都要手工重改插件"）

用法:
    python runs/tools/dsh_state.py --save      # 把当前状态存成基线（确认状态正确后执行）
    python runs/tools/dsh_state.py            # 与基线对比，输出 OK / DRIFT / INFO
    python runs/tools/dsh_state.py --json     # 输出当前状态 JSON

退出码: 0=无漂移  1=有 DRIFT（需要按提示修）
"""
import io, json, os, re, struct, sys

PROFILE = os.path.expanduser("~/.dsh/profiles/desktop")
ASAR = r"<HOME>\AppData\Local\Programs\DeepSeek Harness\resources\app.asar"
BASELINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dsh-baseline.json")
SKILLS_DIR = os.path.expanduser("~/.dsh/skills")

if __name__ == "__main__":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    except Exception:
        pass


# ---------------- semver ----------------
def _parse_ver(v):
    v = v.strip().lstrip("v")
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.\-]+))?(?:\+.*)?$", v)
    if not m:
        return None
    base = tuple(int(x) for x in m.group(1, 2, 3))
    pre = m.group(4)
    return base, (pre.split(".") if pre else None)


def _cmp_pre(a, b):
    # 无 prerelease > 有 prerelease
    if a is None and b is None: return 0
    if a is None: return 1
    if b is None: return -1
    for x, y in zip(a, b):
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            if int(x) != int(y): return 1 if int(x) > int(y) else -1
        elif xn != yn:
            return -1 if xn else 1          # 数字 < 字符串
        else:
            if x != y: return 1 if x > y else -1
    return 0 if len(a) == len(b) else (1 if len(a) > len(b) else -1)


def ver_cmp(v1, v2):
    p1, p2 = _parse_ver(v1), _parse_ver(v2)
    if not p1 or not p2:
        return 0
    if p1[0] != p2[0]:
        return 1 if p1[0] > p2[0] else -1
    return _cmp_pre(p1[1], p2[1])


def _token_ok(ver, tok):
    tok = tok.strip()
    if not tok or tok == "*": return True
    m = re.match(r"^(>=|<=|>|<|=|\^|~)?\s*(.+)$", tok)
    op, target = (m.group(1) or "="), m.group(2)
    c = ver_cmp(ver, target)
    if op == ">=": return c >= 0
    if op == "<=": return c <= 0
    if op == ">":  return c > 0
    if op == "<":  return c < 0
    if op == "=":  return c == 0
    if op == "^":
        return c >= 0 and _parse_ver(ver)[0][0] == _parse_ver(target)[0][0]
    if op == "~":
        a, b = _parse_ver(ver), _parse_ver(target)
        return c >= 0 and a[0][:2] == b[0][:2]
    return True


def range_ok(ver, rng):
    if not rng or rng.strip() == "*": return True
    for alt in rng.split("||"):
        toks = [t for t in re.split(r"\s+", alt.strip()) if t]
        if toks and all(_token_ok(ver, t) for t in toks):
            return True
    return False


# ---------------- asar 读取 ----------------
def asar_reader():
    f = open(ASAR, "rb")
    f.seek(4)
    hb = struct.unpack("<I", f.read(4))[0]
    f.seek(12)
    jl = struct.unpack("<I", f.read(4))[0]
    hdr = json.loads(f.read(jl).decode("utf-8", "replace").rstrip("\x00"))
    data_off = 8 + hb

    def raw(path):
        node = hdr
        for part in path.strip("/").split("/"):
            node = node["files"][part]
        f.seek(data_off + int(node["offset"]))
        return f.read(int(node["size"]))

    def pkg_version(path):
        try:
            return json.loads(raw(path).decode("utf-8", "replace").lstrip("\ufeff")).get("version")
        except Exception:
            return None

    return f, raw, pkg_version


def dsh_version():
    f, raw, pkgv = asar_reader()
    try:
        return pkgv("/dsh/node_modules/@deepseek-ai/dsh-base/package.json")
    finally:
        f.close()


def core_has_agent_team():
    f, raw, _ = asar_reader()
    try:
        t = raw("/dsh/node_modules/@deepseek-ai/dsh-base/cordis.patch.yml").decode("utf-8", "replace")
        rows = re.findall(r"-\s+id:\s*(\S+)", t)
        return "agent-team" in rows, sorted(r for r in rows if "agent" in r or "subagent" in r)
    finally:
        f.close()


# ---------------- profile 状态 ----------------
def read_json(p):
    try:
        return json.load(io.open(p, encoding="utf-8"))
    except Exception:
        return {}


def profile_version():
    f, raw, pkgv = asar_reader()
    try:
        return pkgv("/dsh/node_modules/@deepseek-ai/dsh-base/package.json")
    finally:
        f.close()


def installed_plugins():
    d = read_json(os.path.join(PROFILE, "package.json"))
    out = {}
    for name in (d.get("dependencies") or {}):
        p = os.path.join(PROFILE, "node_modules", name.replace("/", os.sep), "package.json")
        pj = read_json(p)
        if not pj: continue
        eng = ((pj.get("dsh") or {}).get("engines") or {}).get("dsh") or (pj.get("engines") or {}).get("dsh")
        out[name] = {"version": pj.get("version"), "engines_dsh": eng}
    return out


def patch_rows():
    p = os.path.join(PROFILE, "cordis.patch.yml")
    t = io.open(p, encoding="utf-8", errors="replace").read() if os.path.exists(p) else ""
    rows, cur = {}, None
    for ln in t.split("\n"):
        m = re.match(r"^-\s*id:\s*(\S+)", ln)
        if m:
            cur = m.group(1)
            rows[cur] = {"disabled": False, "enabled": None}
            continue
        if cur is None: continue
        if re.match(r"^\s+disabled:\s*true", ln): rows[cur]["disabled"] = True
        m2 = re.match(r"^\s+enabled:\s*(true|false)", ln)
        if m2: rows[cur]["enabled"] = m2.group(1) == "true"
    return rows


def vendor_invariants():
    v = os.path.join(PROFILE, "vendor", "dsh-redteam-mode")
    out = {"exists": os.path.isdir(v), "skills": 0, "list_agents": 0, "internal_recon": 0}
    if not out["exists"]: return out
    sd = os.path.join(v, "skills")
    if os.path.isdir(sd):
        out["skills"] = len([x for x in os.listdir(sd) if x.endswith(".md")])
    y = os.path.join(v, "cordis.patch.yml")
    if os.path.exists(y):
        t = io.open(y, encoding="utf-8", errors="replace").read()
        out["list_agents"] = t.count("list-agents")
        out["internal_recon"] = t.count("redteam-worker-internal-recon")
    return out


def collect():
    bundles = ((read_json(os.path.join(PROFILE, "package.json")).get("dsh") or {})
               .get("profile") or {}).get("bundles") or []
    skills = 0
    if os.path.isdir(SKILLS_DIR):
        skills = len([x for x in os.listdir(SKILLS_DIR) if x.endswith(".md")])
    has_team, team_rows = core_has_agent_team()
    st = {
        "dsh_version": dsh_version(),
        "asar": {"size": os.path.getsize(ASAR),
                 "mtime": __import__("datetime").datetime.fromtimestamp(os.path.getmtime(ASAR)).strftime("%Y-%m-%d %H:%M")},
        "bundles": [str(x) for x in bundles],
        "patch_rows": patch_rows(),
        "vendor": vendor_invariants(),
        "skills_count": skills,
        "plugins": installed_plugins(),
        "core_agent_team": {"present": has_team, "rows": team_rows},
    }
    return st


# ---------------- 检查 ----------------
def check(base, cur):
    drifts, infos = [], []

    # 1) 版本变化（信息）
    if base.get("dsh_version") != cur.get("dsh_version"):
        infos.append("DSH 版本 %s → %s" % (base.get("dsh_version"), cur.get("dsh_version")))
    if base.get("asar", {}).get("mtime") != cur.get("asar", {}).get("mtime"):
        infos.append("app.asar 变更: %s (%s B) → %s (%s B)" % (
            base.get("asar", {}).get("mtime"), base.get("asar", {}).get("size"),
            cur.get("asar", {}).get("mtime"), cur.get("asar", {}).get("size")))

    # 2) bundles 集合与顺序
    b, c = base.get("bundles", []), cur.get("bundles", [])
    removed = [x for x in b if x not in c]
    added = [x for x in c if x not in b]
    if removed:
        drifts.append("profile bundles 少了 %d 项（更新常干这事，会导致能力消失）:\n        %s\n        修复: 用 plugin_manager set_bundle 重新启用，或从备份 package.json 回填" % (len(removed), "\n        ".join(removed)))
    if added:
        infos.append("profile bundles 新增: %s" % ", ".join(added))
    common_b = [x for x in b if x in c]
    common_c = [x for x in c if x in b]
    if common_b != common_c:
        drifts.append("bundle **顺序**变了（顺序=加载优先级，squads/agent-team 抢注册就靠这个）\n        期望: %s\n        实际: %s" % (common_b, common_c))

    # 3) patch 行
    bp, cp = base.get("patch_rows", {}), cur.get("patch_rows", {})
    missing = [k for k in bp if k not in cp]
    if missing:
        drifts.append("cordis.patch.yml 丢了 %d 个定制行: %s\n        修复: 从备份 cordis.patch.yml.bak-* 回填" % (len(missing), ", ".join(missing)))
    extra = [k for k in cp if k not in bp]
    if extra:
        infos.append("cordis.patch.yml 新增定制行: %s（若是有意新增，改完记得 --save 刷新基线）" % ", ".join(extra))
    for k, v in bp.items():
        if k in cp and cp[k] != v:
            drifts.append("patch 行 %s 状态变了: %s → %s" % (k, v, cp[k]))

    # 4) vendor 红队基座
    bv, cv = base.get("vendor", {}), cur.get("vendor", {})
    if bv.get("exists") and not cv.get("exists"):
        drifts.append("vendor/dsh-redteam-mode 丢了！修复: 从 runs/backup/dsh-preupdate-*/vendor 回拷")
    else:
        if cv.get("list_agents", 0) > 0:
            drifts.append("vendor cordis.patch.yml 出现 list-agents 残留（红队预设会报 unavailable）\n        修复: python runs/tools/fix-redteam-preset.py")
        if bv.get("internal_recon", 0) > 0 and cv.get("internal_recon", 0) == 0:
            drifts.append("vendor 缺 internal-recon 预设\n        修复: python runs/tools/fix-redteam-preset.py")
        if cv.get("skills", 0) < bv.get("skills", 0):
            drifts.append("vendor 技能数下降: %d → %d（插件升级覆盖了 vendor）" % (bv.get("skills"), cv.get("skills")))

    # 5) 技能
    if cur.get("skills_count", 0) < base.get("skills_count", 0):
        drifts.append("技能数下降: %d → %d" % (base.get("skills_count"), cur.get("skills_count")))

    # 6) 插件版本 / engines 兼容（更新后最容易坏的地方）
    ver = cur.get("dsh_version") or "0.0.0"
    bp_, cp_ = base.get("plugins", {}), cur.get("plugins", {})
    for name, info in cp_.items():
        bver = (bp_.get(name) or {}).get("version")
        if bver and bver != info.get("version"):
            infos.append("插件 %s 版本 %s → %s" % (name, bver, info.get("version")))
        eng = info.get("engines_dsh")
        if eng and not range_ok(ver, eng):
            drifts.append("插件 %s@%s 要求 dsh %s，当前 %s → **不兼容，会被拒绝激活**\n        修复: 升级该插件或禁用其行（cordis.patch.yml）" % (
                name, info.get("version"), eng, ver))
    gone = [k for k in bp_ if k not in cp_ and not k.startswith("dsh-redteam-mode")]
    if gone:
        infos.append("已卸载/不再声明的插件: %s" % ", ".join(gone))

    # 7) 核心团队能力
    bt, ct = base.get("core_agent_team", {}), cur.get("core_agent_team", {})
    if bt.get("present") and not ct.get("present"):
        drifts.append("核心包不再包含 agent-team（团队能力消失）— 检查 dsh-agent-team 是否被移除")
    elif not bt.get("present") and ct.get("present"):
        infos.append("agent-team 已进入核心包 %s（不再是 profile bundle）" % ct.get("rows"))

    return drifts, infos


def main():
    # --state-file：用给定 JSON 当作"当前状态"，便于测试与对比两份快照
    stfile = None
    for i, a in enumerate(sys.argv):
        if a == "--state-file" and i + 1 < len(sys.argv):
            stfile = sys.argv[i + 1]
    if stfile:
        cur = json.load(io.open(stfile, encoding="utf-8"))
    else:
        cur = collect()
    if "--json" in sys.argv:
        print(json.dumps(cur, ensure_ascii=False, indent=2))
        return 0
    if "--save" in sys.argv:
        io.open(BASELINE, "w", encoding="utf-8", newline="\n").write(
            json.dumps(cur, ensure_ascii=False, indent=2) + "\n")
        print("已写入基线: %s" % BASELINE)
        print("  dsh=%s | bundles=%d | patch行=%d | 插件=%d | 技能=%d" % (
            cur["dsh_version"], len(cur["bundles"]), len(cur["patch_rows"]),
            len(cur["plugins"]), cur["skills_count"]))
        return 0
    if not os.path.exists(BASELINE):
        print("没有基线文件，先执行: python runs/tools/dsh_state.py --save")
        return 1
    base = json.load(io.open(BASELINE, encoding="utf-8"))
    drifts, infos = check(base, cur)
    print("════════ DSH 环境漂移检查 ════════")
    print("基线: dsh=%s bundles=%d  (%s)" % (base.get("dsh_version"), len(base.get("bundles", [])), base.get("asar", {}).get("mtime")))
    print("当前: dsh=%s bundles=%d  (%s)\n" % (cur.get("dsh_version"), len(cur.get("bundles", [])), cur.get("asar", {}).get("mtime")))
    if infos:
        print("── 变化（信息，不一定有问题）──")
        for i in infos: print("  • " + i)
        print()
    if drifts:
        print("── DRIFT（需要处理）──")
        for i, d in enumerate(drifts, 1): print("  %d. %s" % (i, d))
        print("\n结果: %d 项漂移" % len(drifts))
        return 1
    print("结果: OK — 与基线一致，无需改动")
    return 0


if __name__ == "__main__":
    sys.exit(main())
