# -*- coding: utf-8 -*-
"""复扫对比测试（要求 >=2 条，这里写了 3 条）。"""

import os

from platform import duibi, zap_jiexi

GENBAO = os.path.join(os.path.dirname(__file__), "..", "reports", "zap-before.json")
GENHOU = os.path.join(os.path.dirname(__file__), "..", "reports", "zap-after.json")

QIAN = zap_jiexi.jiexi_lujing(GENBAO)
HOU = zap_jiexi.jiexi_lujing(GENHOU)


def test_fenlei_zhengque():
    # before->after：10020/10021/10038 关闭(5)，10049 新增(1)，
    # 10024 风险变化(1)，其余未变(6)
    jg = duibi.duibi_saomiao(QIAN, HOU)
    assert len(jg["yiguanbi"]) == 5
    assert len(jg["xinzeng"]) == 1
    assert len(jg["fengxian_bianhua"]) == 1
    assert len(jg["weibian"]) == 6
    # 正常修复后覆盖率足够，关闭项建议 Verified
    assert jg["fugai_buzu"] is False
    assert all(x["jianyi"] == "Verified" for x in jg["yiguanbi"])


def test_fengxian_bianhua_neirong():
    jg = duibi.duibi_saomiao(QIAN, HOU)
    assert jg["fengxian_bianhua"][0]["qian"]["riskcode"] == "1"
    assert jg["fengxian_bianhua"][0]["hou"]["riskcode"] == "2"


def test_fugai_buzu_buneng_verified():
    # 人为制造覆盖不足：after 只保留首页一个 URL
    hou_shao = [a for a in HOU if a["uri"] == "http://localhost:8000/"]
    jg = duibi.duibi_saomiao(QIAN, hou_shao)
    assert jg["fugai_buzu"] is True
    # 覆盖不足时，已关闭项只能保持 Resolved，不能判 Verified
    assert len(jg["yiguanbi"]) > 0
    assert all(x["jianyi"] == "Resolved" for x in jg["yiguanbi"])
