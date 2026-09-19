# -*- coding: utf-8 -*-
"""授权门禁测试（要求 >=6 条，这里写了 7 条）。"""

import pytest

from platform.fanwei import (
    FanweiYiji,
    jiaoyan_mubiao,
    jiaoyan_zhongdingxiang,
    shengcheng_saomiao_mingling,
)


def test_baimingdan_nei_tongguo():
    # 白名单里的 localhost:8000 应该放行
    jg = jiaoyan_mubiao("http://localhost:8000")
    assert jg["yuxu"] is True
    assert jg["mingzhong"] != ""


def test_baimingdan_ip_tongguo():
    # 127.0.0.1 同时写在 allowed_hosts 与 allowed_ips，应该放行
    jg = jiaoyan_mubiao("http://127.0.0.1:8000")
    assert jg["yuxu"] is True


def test_gongwang_yuju_jujue():
    # 公网域名未列入白名单，必须拒绝
    jg = jiaoyan_mubiao("http://example.com")
    assert jg["yuxu"] is False
    assert "公网" in jg["yuanyin"]


def test_zhongdingxiang_feibaimingdan_beilan():
    # 重定向跳到非白名单主机，必须拦下来
    jg = jiaoyan_zhongdingxiang("http://localhost:8000", "http://evil.com")
    assert jg["yuxu"] is False
    assert "重定向" in jg["yuanyin"]


def test_feifa_url_jujue():
    # 非法 URL（无法解析）必须拒绝，不能静默放行
    jg = jiaoyan_mubiao("这不是一个合法的url")
    assert jg["yuxu"] is False


def test_siwang_weishouquan_jujue():
    # RFC1918 私网地址不会自动视为已授权，必须显式列入 allowed_ips
    jg = jiaoyan_mubiao("http://192.168.1.5:8000")
    assert jg["yuxu"] is False
    assert "allowed_ips" in jg["yuanyin"]


def test_mingling_bixu_guoyan():
    # 命令生成必须过校验：非法目标抛异常，合法目标才返回命令
    with pytest.raises(FanweiYiji):
        shengcheng_saomiao_mingling("http://example.com")
    mingling = shengcheng_saomiao_mingling("http://localhost:8000")
    assert "docker run" in mingling
