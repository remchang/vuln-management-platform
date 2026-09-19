# -*- coding: utf-8 -*-
"""修复回归测试（要求 >=3 条，这里写了 5 条）。

这些测试真的把靶场起在 127.0.0.1 的临时端口上发请求，验证：
修复版补齐了三处安全头、未修复版确实缺头、且修复后原有功能不退化。
全程只访问本机回环地址，不碰任何公网目标。
"""

import http.client
import socketserver
import threading

from target.app import zhizao_chuli


def _qidong(anquan):
    httpd = socketserver.TCPServer(("127.0.0.1", 0), zhizao_chuli(anquan))
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, port


def _tou(port):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/?name=test")
    r = conn.getresponse()
    hd = {k.lower(): v for k, v in r.getheaders()}
    body = r.read().decode("utf-8", "replace")
    conn.close()
    return r.status, hd, body


def test_xiufu_x_frame():
    httpd, port = _qidong(True)
    try:
        status, hd, _ = _tou(port)
        assert status == 200
        assert "x-frame-options" in hd
        assert hd["x-frame-options"].lower() == "deny"
    finally:
        httpd.shutdown()


def test_xiufu_csp():
    httpd, port = _qidong(True)
    try:
        _, hd, _ = _tou(port)
        assert "content-security-policy" in hd
    finally:
        httpd.shutdown()


def test_xiufu_x_content_type():
    httpd, port = _qidong(True)
    try:
        _, hd, _ = _tou(port)
        assert "x-content-type-options" in hd
        assert hd["x-content-type-options"].lower() == "nosniff"
    finally:
        httpd.shutdown()


def test_weixiufu_que_tou():
    # 未修复版必须确实缺这三处头（证明不是一直都有）
    httpd, port = _qidong(False)
    try:
        _, hd, _ = _tou(port)
        assert "x-frame-options" not in hd
        assert "content-security-policy" not in hd
        assert "x-content-type-options" not in hd
    finally:
        httpd.shutdown()


def test_gongneng_bu_tuihua():
    # 修复后反射输入点仍正常工作，原有功能没退化
    httpd, port = _qidong(True)
    try:
        status, _, body = _tou(port)
        assert status == 200
        assert "test" in body
    finally:
        httpd.shutdown()
