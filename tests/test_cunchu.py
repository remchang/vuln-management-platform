# -*- coding: utf-8 -*-
"""漏洞存储与工作流测试（要求 >=6 条，这里写了 7 条）。"""

import pytest

from platform.cunchu import Cunchu
from platform.zhiwen import jisuan_zhiwen

YIGE = [{
    "guize_id": "100", "riskcode": "1", "name": "测试告警", "desc": "d",
    "solution": "s", "cweid": "0", "uri": "http://h/a", "method": "GET", "param": "",
}]


def _xin_cunchu():
    ck = Cunchu()
    ck.chuangjian_pici("t.json", "测试批次")
    ck.daoru_alerts(YIGE, 1)
    return ck, jisuan_zhiwen("100", "http://h/a", "GET", "")


def test_zhuangtai_liuru():
    ck, zw = _xin_cunchu()
    ck.shezhi_zhuangtai(zw, "Confirmed")
    assert ck.huoqu_finding(zw)["zhuangtai"] == "Confirmed"


def test_fuzeren_bixu():
    ck, zw = _xin_cunchu()
    with pytest.raises(ValueError):
        ck.shezhi_fuzeren(zw, "")
    ck.shezhi_fuzeren(zw, "王锐兵")
    assert ck.huoqu_finding(zw)["fuzeren"] == "王锐兵"


def test_chuzhi_liyou_bixu():
    ck, zw = _xin_cunchu()
    with pytest.raises(ValueError):
        ck.shezhi_chuzhi(zw, "")
    ck.shezhi_chuzhi(zw, "确认为误报，参数已校验")
    assert ck.huoqu_finding(zw)["chuzhi_liyou"] != ""


def test_zhuangtai_fanwei():
    ck, zw = _xin_cunchu()
    with pytest.raises(ValueError):
        ck.shezhi_zhuangtai(zw, "不存在的状态")


def test_meiyou_zhengju_buneng_verified():
    # 硬规则：没有修复 Commit 和复扫证据，不能置为 Verified
    ck, zw = _xin_cunchu()
    with pytest.raises(AssertionError):
        ck.shezhi_zhuangtai(zw, "Verified")
    # 只给 commit、不给复扫批次，仍然不行
    ck.shezhi_chuzhi(zw, "已修复", xiufu_commit="deadbeef")
    with pytest.raises(AssertionError):
        ck.shezhi_zhuangtai(zw, "Verified")


def test_you_zhengju_ke_verified():
    # 同时具备修复 Commit 与复扫批次证据时，才能 Verified
    ck, zw = _xin_cunchu()
    ck.shezhi_chuzhi(zw, "已修复安全头", xiufu_commit="deadbeef")
    ck.guanlian_fusaomiao(zw, 2)
    ck.shezhi_zhuangtai(zw, "Verified")
    assert ck.huoqu_finding(zw)["zhuangtai"] == "Verified"


def test_an_zhuangtai_chaxun():
    ck, zw = _xin_cunchu()
    ck.shezhi_zhuangtai(zw, "Confirmed")
    liebiao = ck.liebiao_findings(zhuangtai="Confirmed")
    assert len(liebiao) == 1
    assert liebiao[0]["zhiwen"] == zw
