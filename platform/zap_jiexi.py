# -*- coding: utf-8 -*-
"""
ZAP 报告解析模块。

踩过的坑（重要，决定了这里为什么这么写）：
ZAP 导出的 Traditional JSON 长这样：
    {
      "site": [
        {
          "@name": "http://localhost:8000",
          "alerts": [
            {
              "pluginid": "10020",
              "riskcode": "1",
              "name": "...",
              "desc": "<p>HTML...</p>",
              "solution": "<p>HTML...</p>",
              "cweid": "16",
              "instances": [
                {"uri": "...", "method": "GET", "param": "", "evidence": ""},
                {"uri": "...", "method": "GET", "param": "", "evidence": ""}
              ]
            }
          ]
        }
      ]
    }

最容易犯的错误是“假设每条 alert 顶层就有 url”。实际上：规则级别的
字段（pluginid / riskcode / name / desc / solution / cweid）在 alert 层，
而具体出现在哪个页面、哪个参数、哪条证据，都在 instances[] 里。一条
alert 可能对应几十个实例，每个实例是独立的发现位置。所以解析时必须
按 instance 展开，否则会漏掉大量多处实例。

另外 desc / solution 里是 HTML 文本，绝不能当可信 HTML 执行，展示前要
净化成纯文本（见 qu_html）。

本模块对所有可能缺失、类型异常的字段都做了防御，绝不因为报告格式
稍有不同就整体崩溃。
"""

import json
import re


def qu_html(html):
    """把 ZAP 报告里的 HTML 片段净化成纯文本。

    为什么要写这个函数：desc / solution 来自扫描器，属于“不可信内容”，
    一旦在界面里直接当 HTML 渲染，就可能出现脚本注入。这里只保留文字，
    去掉标签、脚本/样式块和常见实体，并折叠多余空白。
    """
    if not html:
        return ""
    if not isinstance(html, str):
        try:
            html = str(html)
        except Exception:
            return ""
    # 去掉 <script> 和 <style> 整块内容
    html = re.sub(r"<(script|style)[^>]*>.*?</\1>",
                  "", html, flags=re.IGNORECASE | re.DOTALL)
    # 去掉剩余所有标签
    html = re.sub(r"<[^>]+>", "", html)
    # 处理常见 HTML 实体
    tihuan = [
        ("&lt;", "<"), ("&gt;", ">"), ("&amp;", "&"),
        ("&quot;", '"'), ("&#39;", "'"), ("&nbsp;", " "),
        ("&apos;", "'"),
    ]
    for old, new in tihuan:
        html = html.replace(old, new)
    # 折叠空白
    html = re.sub(r"\s+", " ", html).strip()
    return html


def jiexi_lujing(lujing):
    """从文件读取并解析 ZAP 报告。"""
    with open(lujing, "r", encoding="utf-8") as f:
        shuju = json.load(f)
    return jiexi_shuju(shuju)


def jiexi_shuju(shuju):
    """解析 ZAP Traditional JSON 数据为展平后的实例列表。

    返回的每个元素形如：
        {
            "guize_id": "10020",   # 规则 ID（pluginid）
            "riskcode": "1",
            "name": "X-Frame-Options Header Not Set",
            "desc": "净化后的纯文本描述",
            "solution": "净化后的纯文本建议",
            "cweid": "16",
            "wascid": "15",
            "site_name": "http://localhost:8000",
            "site_host": "localhost",
            "site_port": "8000",
            "uri": "实例实际 URL",
            "method": "GET",
            "param": "触发参数名",
            "evidence": "证据片段"
        }
    """
    jieguo = []
    if not isinstance(shuju, dict):
        return jieguo

    sites = shuju.get("site")
    if not sites:
        # 空 site 直接返回空列表，不报错
        return jieguo
    if not isinstance(sites, list):
        sites = [sites]

    for site in sites:
        if not isinstance(site, dict):
            continue
        site_name = site.get("@name") or ""
        site_host = site.get("@host") or ""
        site_port = site.get("@port") or ""

        alerts = site.get("alerts") or []
        if not isinstance(alerts, list):
            continue

        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            guize_id = str(alert.get("pluginid", "") or "")
            riskcode = str(alert.get("riskcode", "") or "")
            name = alert.get("name") or ""
            desc = qu_html(alert.get("desc", ""))
            solution = qu_html(alert.get("solution", ""))
            cweid = str(alert.get("cweid", "") or "")
            wascid = str(alert.get("wascid", "") or "")

            instances = alert.get("instances")
            if not instances:
                # 极少数报告没有 instances，退化为单条，用 site 名兜底
                instances = [{
                    "uri": site_name,
                    "method": "GET",
                    "param": "",
                    "evidence": "",
                }]
            if not isinstance(instances, list):
                instances = [instances]

            for ins in instances:
                if not isinstance(ins, dict):
                    continue
                uri = ins.get("uri") or site_name
                method = ins.get("method") or "GET"
                param = ins.get("param") or ""
                evidence = ins.get("evidence") or ""
                jieguo.append({
                    "guize_id": guize_id,
                    "riskcode": riskcode,
                    "name": name,
                    "desc": desc,
                    "solution": solution,
                    "cweid": cweid,
                    "wascid": wascid,
                    "site_name": site_name,
                    "site_host": site_host,
                    "site_port": site_port,
                    "uri": uri,
                    "method": method,
                    "param": param,
                    "evidence": evidence,
                })
    return jieguo
