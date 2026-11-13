#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
全链语义审计探针（按「每个环节是干什么的」审计，不只查当轮改动点）
==================================================================
背景（2026-11-12 用户质问后立此为据）：JSON 是多轮增量改出来的，历次只验证当轮改动点，
「环节忘记定义键」这类断链长期存活。本探针把链路语义固化成不变量，每次改完 JSON 必跑：

  ① 链序与边界：阶段0_开始 在链首、阶段99_结束 在链尾。
  ② 输入字段存储键（#71）：环节对象里的遗留「输入字段」若残留，必须与推导输入一致
     （推导输入 ≡ 上一环节对外清单；过滤表/键映射/纯形态检测表为透传型，向上找）。
  ③ 键链完整：非纯透传的输出字段（计算型）必须自带 api_key_name（键在诞生处声明）；
     纯透传输出（单条无条件变量规则取同名字段）允许继承上游同名键，全链未标注则告警。
  ④ 引用闭合（#2003/#7）：所有规则的条件/取值「字段」∈ 本环节输入字段
     ——与上一环节对外清单同名者即引用输入（即使本环节也声明了同名字段，不算自引用）；
     短路表禁止引用「仅在本环节输出、输入没有」的字段（并行语义，应拆环节）；
     提示词正文引用不做静态校验。
  ⑤ 键映射一致性：桶内字段不在上游对外清单 → 孤儿告警（#75 允许保留）；
     上游输出字段声明 键层=明细行 的字段，改名条目应落在「明细行」桶。
  ⑥ 模式形态：过滤表 = 只写规则不写字段键；纯形态检测表 = 无输出字段、规则挂环节级；
     键映射 = 只有「键映射」改名表。
  ⑦ 层序铁律（2026-11-13 用户定）：定义层的模式（短路表/提示词）输出字段必须
     单据头层在前、明细行层在后，两层不得交错（缺省未声明键层视同单据头）。

用法：python3 probes/probe_chain.py [main-config.json 路径]（缺省 = 仓库根 main-config.json）
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CFG = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "..", "main-config.json")

errors, warns = [], []


def E(msg):
    errors.append(msg)


def W(msg):
    warns.append(msg)


MODES = ("短路表", "过滤表", "检测表", "提示词", "键映射")
PASSTHROUGH_MODES = ("过滤表", "键映射")


def load():
    with open(CFG, encoding="utf-8") as f:
        return json.load(f)


def is_passthrough_decl(fd):
    """纯透传声明 = 单条无条件变量规则、取同名字段（README #2005 透传写法）"""
    rules = (fd or {}).get("规则") or []
    if len(rules) != 1:
        return False
    r = rules[0]
    out = r.get("输出") or {}
    return (not r.get("条件")) and out.get("类型") == "变量" and out.get("字段") == _cur_field


_cur_field = None  # is_passthrough_decl 需要当前字段名（逐字段置入）


def collect_refs(node, refs):
    """递归收集规则里的条件/取值「字段」引用"""
    if isinstance(node, dict):
        if isinstance(node.get("字段"), str):
            refs.add(node["字段"])
        if isinstance(node.get("输出"), dict) and isinstance(node["输出"].get("字段"), str):
            refs.add(node["输出"]["字段"])
        for v in node.values():
            collect_refs(v, refs)
    elif isinstance(node, list):
        for v in node:
            collect_refs(v, refs)


def stage_mode(st):
    m = st.get("模式")
    if m in MODES:
        return m
    if st.get("输出字段") or isinstance(st.get("规则"), list):
        return "短路表"
    return "提示词"


def is_passthrough_stage(sk, logic, keys):
    """透传型 = 过滤表 / 键映射 / 无「输出字段」的纯形态检测表"""
    st = logic.get(sk) or {}
    m = stage_mode(st)
    return m in PASSTHROUGH_MODES or (m == "检测表" and not st.get("输出字段"))


def external_fields(sk, logic, keys, seen=None):
    """编辑器 stageFieldList 同款推导：透传型向上找（递归）"""
    seen = seen or set()
    if sk in seen:
        return []
    seen.add(sk)
    if is_passthrough_stage(sk, logic, keys):
        i = keys.index(sk)
        return external_fields(keys[i - 1], logic, keys, seen) if i > 0 else []
    return list(((logic.get(sk) or {}).get("输出字段") or {}).keys())


def upstream_meta(sk, logic, keys):
    """穿过透传环节向上找，取最近一个有「输出字段」声明环节的 {字段: (键, 键层)}"""
    i = keys.index(sk)
    for j in range(i - 1, -1, -1):
        sk2 = keys[j]
        if is_passthrough_stage(sk2, logic, keys):
            continue
        out = (logic.get(sk2) or {}).get("输出字段") or {}
        meta = {}
        for name, fd in out.items():
            fd = fd if isinstance(fd, dict) else {}
            meta[name] = (fd.get("api_key_name"), fd.get("键层") or "单据头")
        return meta
    return {}


def main():
    cfg = load()
    logic = cfg.get("转换逻辑") or {}
    keys = list(logic.keys())
    if not keys:
        E("转换逻辑为空")
        print_report()
        return

    # ① 链序与边界
    if not keys[0].startswith("阶段0"):
        E(f"链首不是「阶段0_开始」边界环节，而是 {keys[0]}")
    if not keys[-1].startswith("阶段99"):
        E(f"链尾不是「阶段99_结束」边界环节，而是 {keys[-1]}")

    for sk in keys:
        st = logic.get(sk) or {}
        m = stage_mode(st)
        out = st.get("输出字段") or {}
        idx = keys.index(sk)
        ins = external_fields(keys[idx - 1], logic, keys) if idx > 0 else []
        um = upstream_meta(sk, logic, keys)

        # ② 遗留「输入字段」存储键若残留，必须与推导输入一致（#71：输入=推导值）
        legacy = st.get("输入字段")
        if legacy is not None and list(legacy) != ins:
            W(f"{sk}（{m}）残留「输入字段」存储键与推导输入不一致（编辑器/引擎均不读，建议清理）")

        # ③ 键链完整
        for name, fd in out.items():
            globals()["_cur_field"] = name
            fd = fd if isinstance(fd, dict) else {}
            if fd.get("api_key_name") is None:
                if is_passthrough_decl(fd):
                    if um.get(name, (None,))[0] is None:
                        W(f"{sk}.{name}：纯透传且全链未标注键（回退字段名）")
                else:
                    E(f"{sk}.{name}：计算型输出字段缺 api_key_name（键必须在诞生处声明）")

        # ④ 引用闭合（提示词正文不做静态校验）
        refs = set()
        collect_refs(st.get("规则"), refs)            # 环节级规则（过滤/检测）
        for name, fd in out.items():                  # 字段级规则（短路/提示词）
            collect_refs((fd or {}).get("规则"), refs)
        if m in ("短路表", "检测表", "过滤表"):
            bad = refs - set(ins)
            if bad:
                E(f"{sk}（{m}）规则引用了非输入字段：{sorted(bad)}")
            if m == "短路表":
                # 与输入同名者引用的是输入字段，合法；只有「仅在本环节输出」才是自引用违规
                self_ref = (refs & set(out.keys())) - set(ins)
                if self_ref:
                    E(f"{sk}（短路表）引用同环节独有输出字段（违反并行语义，应拆环节）：{sorted(self_ref)}")

        # ⑥ 模式形态
        if m == "过滤表" and out:
            E(f"{sk}（过滤表）不应有「输出字段」（透传型免维护字段）")
        if m == "检测表" and not out and not (st.get("规则") or []):
            E(f"{sk}（检测表纯形态）没有任何规则")
        if m == "键映射":
            extra = set(st.keys()) & {"输出字段", "规则"}
            if extra:
                E(f"{sk}（键映射）残留独占键 {sorted(extra)}（应只留「键映射」）")

        # ⑦ 层序（建议型规范，2026-11-13 用户定）：定义层的模式（短路表/提示词）的「输出字段」
        #    建议单据头层在前、明细行层在后、两层字段不得交错——缺省（未声明键层）视同单据头。
        #    ⚠ 只提示不阻断（W，非 E）：编辑器允许长按拖拽任意调整定义顺序，违规排序不作为硬闸；
        #    违序 JSON 由 Editor 如实渲染（不自动重排、不拦保存）。仅定义层模式适用，透传型不查。
        if m in ("短路表", "提示词") and isinstance(out, dict) and out:
            seen_detail = False
            for name, fd in out.items():
                layer = (fd or {}).get("键层") or "单据头" if isinstance(fd, dict) else "单据头"
                if layer == "明细行":
                    seen_detail = True
                elif seen_detail:
                    W(f"{sk}（{m}）输出字段「{name}」（单据头）排在明细行字段之后，与层序建议不一致（单据头在前、明细行在后；建议型，不阻断）")

    # ⑤ 键映射一致性
    for sk in keys:
        st = logic.get(sk) or {}
        if stage_mode(st) != "键映射":
            continue
        km = st.get("键映射") or {}
        rows = external_fields(sk, logic, keys)
        um = upstream_meta(sk, logic, keys)
        for layer, bucket in km.items():
            for name in bucket:
                if name not in rows:
                    W(f"{sk} 键映射.{layer}.{name}：上游暂无此字段（孤儿项，#75 允许保留，上游再输出即生效）")
                if layer == "明细行" and name in um:
                    _, up_layer = um[name]
                    if up_layer != "明细行":
                        W(f"{sk} 键映射.明细行.{name}：上游键层声明为「{up_layer}」，改名却落在明细行桶（层不一致，请确认）")

    print_report()


def print_report():
    for e in errors:
        print("  ✗", e)
    for w in warns:
        print("  ⚠", w)
    print(f"结果：{len(errors)} 错误 / {len(warns)} 告警")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
