# -*- coding: utf-8 -*-
"""解析与指纹去重测试（要求 >=8 条，这里写了 10 条）。"""

import os

from platform import zap_jiexi, zhiwen
from platform.zhiwen import jisuan_zhiwen
from platform.cunchu import Cunchu

GENBAO = os.path.join(os.path.dirname(__file__), "..", "reports", "zap-before.json")


def test_jiexi_beisai_tiaoshu():
    # before 报告应有 12 条发现（8 条 alert，其中 10020/10021 各 2 实例，10099 各 2 实例）
    jieguo = zap_jiexi.jiexi_lujing(GENBAO)
    assert len(jieguo) == 12


def test_duo_shili_bu_lou():
    # 10020 有 2 个实例，应展开成 2 条发现，不能只取顶层
    jieguo = zap_jiexi.jiexi_lujing(GENBAO)
    tiaojian = [x for x in jieguo if x["guize_id"] == "10020"]
    assert len(tiaojian) == 2


def test_qu_html_wu_biaoqian():
    # desc 里的 HTML 必须被净化成纯文本，不能残留标签
    jieguo = zap_jiexi.jiexi_lujing(GENBAO)
    tiao = [x for x in jieguo if x["guize_id"] == "10020"][0]
    assert "<" not in tiao["desc"]
    assert "X-Frame-Options" in tiao["desc"]


def test_que_ziduan_bu_bengkui():
    # 缺字段（没有 name/desc/riskcode，且 instances 退化）不应崩溃
    shuju = {
        "site": [{
            "@name": "http://x",
            "alerts": [{
                "pluginid": "1",
                "instances": [{"uri": "http://x/a", "method": "GET", "param": ""}],
            }],
        }]
    }
    jieguo = zap_jiexi.jiexi_shuju(shuju)
    assert len(jieguo) == 1
    assert jieguo[0]["name"] == ""
    assert jieguo[0]["desc"] == ""


def test_kong_site():
    # 空 site 或根本没有 site，都应返回空列表而非报错
    assert zap_jiexi.jiexi_shuju({"site": []}) == []
    assert zap_jiexi.jiexi_shuju({}) == []
    assert zap_jiexi.jiexi_shuju(None) == []


def test_ziduan_leixing_yichang():
    # desc 不是字符串（比如数字）时也能处理
    shuju = {
        "site": [{
            "@name": "http://x",
            "alerts": [{
                "pluginid": "1",
                "desc": 123,
                "instances": [{"uri": "http://x/a"}],
            }],
        }]
    }
    jieguo = zap_jiexi.jiexi_shuju(shuju)
    assert jieguo[0]["desc"] == "123"


def test_suiji_chaxun_guifan():
    # 随机查询值（缓存破坏者 _=xxx）必须规范掉，否则同一资源被拆成多条
    a = jisuan_zhiwen("100", "http://h/p?_=111&x=1", "GET", "")
    b = jisuan_zhiwen("100", "http://h/p?_=222&x=1", "GET", "")
    assert a == b


def test_lujing_canshu_qufen():
    # 不同参数、不同路径必须区分开，不能误合并
    e = jisuan_zhiwen("100", "http://h/p1", "GET", "q")
    f = jisuan_zhiwen("100", "http://h/p1", "GET", "")
    assert e != f
    g = jisuan_zhiwen("100", "http://h/p1", "GET", "")
    h = jisuan_zhiwen("100", "http://h/p2", "GET", "")
    assert g != h
    # 真实业务参数 id=1 与 id=2 不能误合并
    i = jisuan_zhiwen("100", "http://h/r?id=1", "GET", "")
    j = jisuan_zhiwen("100", "http://h/r?id=2", "GET", "")
    assert i != j


def test_chongfu_daoru_bu_zengzhi():
    # 同一份报告重复导入，Finding 数量不应增殖
    alerts = zap_jiexi.jiexi_lujing(GENBAO)
    ck = Cunchu()
    p1 = ck.chuangjian_pici("before.json", "第一批")
    ck.daoru_alerts(alerts, p1)
    di_yi_ci = ck.jishu_findings()
    p2 = ck.chuangjian_pici("before.json", "第二批重复")
    ck.daoru_alerts(alerts, p2)
    assert ck.jishu_findings() == di_yi_ci
    assert ck.jishu_findings() == 12


def test_pici_lishi_baoliu():
    # 重复导入会在出现历史里累加批次记录，而不是覆盖
    alerts = zap_jiexi.jiexi_lujing(GENBAO)
    ck = Cunchu()
    zhiwen = jisuan_zhiwen("10020", "http://localhost:8000/", "GET", "")
    ck.chuangjian_pici("before.json", "批次1")
    ck.daoru_alerts(alerts, 1)
    ck.chuangjian_pici("before.json", "批次2")
    ck.daoru_alerts(alerts, 2)
    jilu = ck.chuchang_jilu(zhiwen)
    assert len(jilu) == 2
