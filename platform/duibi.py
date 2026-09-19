# -*- coding: utf-8 -*-
"""
复扫对比模块。

导入 before / after 两份报告，按指纹分类：
    新增        ：after 有、before 没有
    未变        ：两边都有且风险等级一致
    风险变化    ：两边都有但 riskcode 变了
    已关闭      ：before 有、after 没有

最难处理的是“假关闭”：
扫描器是爬到哪扫到哪。如果 after 这次覆盖的 URL 数量明显少于 before，
那么“某条洞在 after 里没了”很可能只是“这次根本没爬到那个页面”，
而不是“真修好了”。这种情况绝不能把状态直接跳到 Verified，只能保持
Resolved（已修复待验证），并给出“覆盖不足”的警告。
"""

from .zhiwen import jisuan_zhiwen

# 覆盖率阈值：after 覆盖 URL 数 / before 覆盖 URL 数 低于该值即认为覆盖不足
FUGAIBUZU_yuzhi = 0.7


def _zhijian_map(alerts):
    """告警列表 → {指纹: 告警}。"""
    m = {}
    for a in alerts:
        z = jisuan_zhiwen(
            a.get("guize_id", ""), a.get("uri", ""),
            a.get("method", "GET"), a.get("param", ""),
        )
        m[z] = a
    return m


def _fugai_urls(alerts):
    return set(a.get("uri", "") for a in alerts if a.get("uri"))


def duibi_saomiao(qian_alerts, hou_alerts):
    """对比两份报告，返回分类结果。

    返回结构：
        {
            "xinzeng": [告警...],
            "weibian": [告警...],
            "fengxian_bianhua": [{"qian": 告警, "hou": 告警}...],
            "yiguanbi": [{"alert": 告警, "jianyi": "Verified"/"Resolved"}...],
            "fugai_buzu": True/False,
            "fugai_zu": 0.xx,
            "qian_shu": N, "hou_shu": M
        }
    """
    qian_map = _zhijian_map(qian_alerts)
    hou_map = _zhijian_map(hou_alerts)
    qian_zhiwen = set(qian_map)
    hou_zhiwen = set(hou_map)

    xinzeng = [hou_map[z] for z in (hou_zhiwen - qian_zhiwen)]
    yiguanbi_zhiwen = qian_zhiwen - hou_zhiwen

    weibian = []
    fengxian_bianhua = []
    for z in (qian_zhiwen & hou_zhiwen):
        if qian_map[z].get("riskcode") != hou_map[z].get("riskcode"):
            fengxian_bianhua.append({"qian": qian_map[z], "hou": hou_map[z]})
        else:
            weibian.append(hou_map[z])

    # 覆盖率检查
    qian_urls = _fugai_urls(qian_alerts)
    hou_urls = _fugai_urls(hou_alerts)
    if not qian_urls:
        fugai_zu = 1.0
    else:
        fugai_zu = len(hou_urls) / len(qian_urls)
    fugai_buzu = fugai_zu < FUGAIBUZU_yuzhi

    yiguanbi = []
    for z in yiguanbi_zhiwen:
        # 覆盖不足时不能判定为修复关闭，只能保持 Resolved
        jianyi = "Resolved" if fugai_buzu else "Verified"
        yiguanbi.append({"alert": qian_map[z], "jianyi": jianyi})

    return {
        "xinzeng": xinzeng,
        "weibian": weibian,
        "fengxian_bianhua": fengxian_bianhua,
        "yiguanbi": yiguanbi,
        "fugai_buzu": fugai_buzu,
        "fugai_zu": round(fugai_zu, 3),
        "qian_shu": len(qian_alerts),
        "hou_shu": len(hou_alerts),
    }
