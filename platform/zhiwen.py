# -*- coding: utf-8 -*-
"""
稳定指纹与去重模块。

为什么需要“稳定指纹”：
同一份报告重复导入，或者同一资源在不同批次里被扫到，都不应该凭空
多出新的 Finding。相反，像 ?_=12345 这种缓存破坏参数，又会让同一个
资源的每次请求看起来都不一样，从而被错误地拆成很多条。指纹要解决
这两头的问题：

  - 拆不开：把随机查询值规范化，让同一资源稳定合并；
  - 合错了：只在“确实是随机参数”时才规范化，不能把真实的业务参数
            （比如 id=1、id=2 代表两个不同资源）也一并抹掉。

指纹组成：规则 ID + 规范化 origin + HTTP method + 路径 + 参数。
其中“参数”指 ZAP 报出来的触发参数名（param），它本身就是区分不同
注入点的关键，必须纳入指纹，否则不同参数的同类漏洞会被误合并。

关于随机查询值的处理（容易误合并/漏合并的反例见文件末尾 docstring
以及 docs/实验报告.md）：
  - 已知缓存破坏者参数名（_、cachebuster、_dc、rand、random、ts、
    timestamp 等）：值规范为占位符 <随机值>；
  - 纯数字且长度 >= 13 的值（典型时间戳）：规范为 <时间戳>；
  - 其余参数名和值原样保留并排序，保证稳定。
"""

import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

# 已知“缓存破坏者/随机参数”的名称（小写）。这些参数的值基本都是随机的，
# 不应该参与指纹区分，否则同一资源会被拆成无数条。
ZHIDING_SUIJI_CAN = {
    "_", "_dc", "cachebuster", "cb", "rand", "random",
    "ts", "timestamp", "t", "nonce", "v_", "_t",
}


def _guifanhua_can_query(query):
    """把查询串里的随机参数值规范掉，但保留真实业务参数。"""
    if not query:
        return ""
    try:
        params = parse_qsl(query, keep_blank_values=True)
    except Exception:
        return query

    xin = []
    for k, v in params:
        kl = (k or "").lower()
        shi_suiji = False
        # 名称在已知随机参数集合里
        if kl in ZHIDING_SUIJI_CAN:
            shi_suiji = True
        # 名称以常见随机前缀开头
        elif kl.startswith("_") or kl.startswith("cache"):
            shi_suiji = True
        # 值是 13 位以上的纯数字（典型毫秒时间戳）
        elif isinstance(v, str) and re.fullmatch(r"\d{13,}", v):
            shi_suiji = True
        # 值是较长的十六进制随机串
        elif isinstance(v, str) and re.fullmatch(r"[0-9a-fA-F]{16,}", v):
            shi_suiji = True

        if shi_suiji:
            xin.append((k, "<随机值>"))
        else:
            xin.append((k, v))

    # 排序保证“同一组参数、不同顺序”也算同一个指纹
    xin.sort()
    try:
        return urlencode(xin)
    except Exception:
        return query


def jisuan_zhiwen(guize_id, uri, method, param):
    """计算一条发现的稳定指纹。

    参数：
        guize_id: ZAP 规则 ID（pluginid）
        uri:      实例 URL（含路径与查询）
        method:   HTTP 方法
        param:    触发参数名（ZAP instance 的 param 字段）
    返回：字符串指纹。
    """
    guize_id = str(guize_id or "").strip()
    try:
        p = urlparse(uri or "")
    except Exception:
        p = None
    if p is None:
        origin = ""
        path = uri or "/"
        query = ""
    else:
        origin = urlunparse((p.scheme, p.netloc, "", "", "", ""))
        path = p.path or "/"
        query = _guifanhua_can_query(p.query)

    method = (method or "GET").upper().strip()
    param = (param or "").strip()

    return "|".join([guize_id, origin, method, path, query, param])


"""
三个容易误合并 / 漏合并的反例（也是实验报告里的思考题素材）：

反例1（漏合并 / 误拆分）：同一资源带缓存破坏者
    /page?_=111&x=1   与   /page?_=222&x=1
    若不做规范化，会被当成两条。处理：把 _ 的值规范成 <随机值>，
    二者指纹一致 → 合并为一条。

反例2（误合并）：不同业务资源被错误抹平
    /report?id=1   与   /report?id=2
    id 是真实的资源标识，不是随机参数，绝不能规范化。处理：id 不在
    已知随机参数集合，也未命中“13位纯数字”规则（2 位数字），因此
    原样保留 → 两条不同指纹，不会误合并。

反例3（漏合并）：同一资源不同扫描批次里参数顺序不同
    /s?a=1&b=2   与   /s?b=2&a=1
    查询参数顺序不稳定会导致指纹不同。处理：规范化时对参数排序，
    二者指纹一致 → 合并。
"""
