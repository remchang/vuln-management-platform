# -*- coding: utf-8 -*-
"""
授权门禁模块（本实验的第一道关）。

为什么单独做一个门禁：
安全扫描最危险的地方不是“扫不出洞”，而是“扫错了对象”。
一个顺手的脚本很容易把 localhost 写成某个公网域名，或者在重定向
里被带到一个不属于自己的主机上。为此必须把“哪些目标允许扫”和
“实际要扫的目标”强制分开校验，扫描命令只能在白名单命中后才生成。

设计要点：
1. 白名单配置放在 fanwei-peizhi.json，和代码解耦，便于资产所有者修改。
2. 默认只允许 localhost / 127.0.0.1 / host.docker.internal / 本 Compose
   服务名；公网域名一律拒绝。
3. 明确禁止把 RFC1918 私网（192.168.x.x、10.x.x.x 等）自动当成已授权，
   必须显式写进 allowed_ips 才放行。
4. 重定向目标也必须过校验，否则停止。
5. shengcheng_saomiao_mingling 只有在校验通过时才返回命令，否则抛异常，
   从机制上保证“先校验、后扫描”。
"""

import json
import os
import ipaddress
from urllib.parse import urlparse

# 配置文件默认位置：与本模块同目录的 fanwei-peizhi.json
MOREN_PEIZHI_LUJING = os.path.join(os.path.dirname(__file__), "fanwei-peizhi.json")

# 门禁校验不通过时抛出的异常，调用方必须捕获并停止
class FanweiYiji(Exception):
    """授权范围越界异常，表示目标未通过白名单校验。"""
    pass


def duru_peizhi(lujing=None):
    """读取授权白名单配置。

    参数为 None 时使用默认路径。配置缺失时直接抛错，不静默用空配置，
    避免“配置没读到就等于全部放行”这种危险默认。
    """
    lujing = lujing or MOREN_PEIZHI_LUJING
    with open(lujing, "r", encoding="utf-8") as f:
        return json.load(f)


def _shifou_ip(zifu):
    """判断一个字符串能否解析成 IP 地址。"""
    try:
        ipaddress.ip_address(zifu)
        return True
    except ValueError:
        return False


def jiaoyan_mubiao(url, peizhi=None):
    """扫描前强制校验目标 URL。

    返回结构化结果：
        {
            "yuxu": True/False,      # 是否允许
            "yuanyin": "拒绝原因",    # 拒绝时填写
            "mingzhong": "命中的白名单项"  # 允许时填写
        }

    校验顺序：
        1) URL 能否解析、是否含 http/https；
        2) 主机是否精确命中 allowed_hosts；
        3) 是否命中 allowed_urls（按主机+端口匹配）；
        4) 若是 IP：只有在 allowed_ips 显式列出才放行，
           私网/回环 IP 不会自动通过；
        5) 其余域名（含公网域名）一律拒绝。
    """
    peizhi = peizhi or duru_peizhi()

    # 第一步：URL 本身是否合法
    try:
        jiexi = urlparse(url)
    except Exception:
        return {"yuxu": False, "yuanyin": "URL 无法解析", "mingzhong": ""}
    if not jiexi.scheme or not jiexi.netloc:
        return {"yuxu": False, "yuanyin": "缺少协议或主机，疑似非法 URL", "mingzhong": ""}
    if jiexi.scheme not in ("http", "https"):
        return {"yuxu": False, "yuanyin": "仅允许 http/https 协议", "mingzhong": ""}

    zhujiming = (jiexi.hostname or "").lower()
    duankou = jiexi.port

    # 第二步：精确命中主机白名单
    yunxu_zhujis = set(h.lower() for h in peizhi.get("allowed_hosts", []))
    if zhujiming in yunxu_zhujis:
        return {"yuxu": True, "yuanyin": "", "mingzhong": zhujiming}

    # 第三步：命中允许 URL 列表（按主机 + 端口匹配）
    for u in peizhi.get("allowed_urls", []):
        p = urlparse(u)
        if p.hostname and p.hostname.lower() == zhujiming:
            # 端口相等，或者一边是默认端口另一边省略，都算匹配
            p_duankou = p.port
            if p_duankou == duankou:
                return {"yuxu": True, "yuanyin": "", "mingzhong": u}
            if p_duankou is None and duankou in (80, 443):
                return {"yuxu": True, "yuanyin": "", "mingzhong": u}
            if duankou is None and p_duankou in (80, 443):
                return {"yuxu": True, "yuanyin": "", "mingzhong": u}

    # 第四步：若是 IP，必须显式列入 allowed_ips
    if _shifou_ip(zhujiming):
        yunxu_ips = set(i.lower() for i in peizhi.get("allowed_ips", []))
        if zhujiming in yunxu_ips:
            return {"yuxu": True, "yuanyin": "", "mingzhong": zhujiming}
        # 关键：私网、回环之外的 IP 不能自动视为已授权
        return {"yuxu": False, "yuanyin": "该 IP 未显式列入 allowed_ips，私网/回环不会自动放行", "mingzhong": ""}

    # 第五步：走到这里说明是域名且不在白名单，按公网域名拒绝
    return {"yuxu": False, "yuanyin": "公网域名未列入白名单，拒绝扫描", "mingzhong": ""}


def jiaoyan_zhongdingxiang(chushi_url, mudi_url, peizhi=None):
    """校验重定向目标。

    有些扫描器会跟随 302 跳走，如果跳转到了非白名单主机，必须停止。
    返回结构同 jiaoyan_mubiao。
    """
    peizhi = peizhi or duru_peizhi()
    jg = jiaoyan_mubiao(mudi_url, peizhi)
    if not jg["yuxu"]:
        return {
            "yuxu": False,
            "yuanyin": "重定向目标 %s 不在白名单：%s" % (mudi_url, jg["yuanyin"]),
            "mingzhong": "",
        }
    return jg


def shengcheng_saomiao_mingling(url, peizhi=None):
    """只有白名单命中后才生成 ZAP 扫描命令，否则抛 FanweiYiji。

    这是“先校验后扫描”的硬性落点：调用方必须先看到返回的命令，
    才能去执行，从而不可能在门禁之外直接扫到未授权目标。
    """
    jg = jiaoyan_mubiao(url, peizhi)
    if not jg["yuxu"]:
        raise FanweiYiji("目标未通过授权校验，拒绝生成扫描命令：" + jg["yuanyin"])

    # 返回容器路线的示意命令（原生 java 路线见 scripts/saomiao.ps1）。
    # 注意：本机并没有 ZAP，这里只是“如果通过校验，应该长什么样”。
    mingling = (
        "docker run --rm -t zaproxy/zap-stable "
        "zap-baseline.py -t %s -J zap-out.json" % url
    )
    return mingling
