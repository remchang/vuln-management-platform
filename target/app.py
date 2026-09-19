# -*- coding: utf-8 -*-
"""
本地被测靶场应用（用 Python 标准库 http.server 实现，零额外依赖）。

设计目的：给“修复—复扫”闭环提供一个能真实跑起来的本地目标。
这个“未修复版”故意：
  - 不设置任何安全响应头（没有 CSP / X-Frame-Options / X-Content-Type-Options）；
  - 留一个反射型输入点（name 参数直接回显到页面，未转义），
    对应 ZAP 规则 10020 / 10021 / 10038 这类“缺安全头”告警会被扫出来。

修复版见 app_yiuxiu.py，它只是把 anquan=True 传进来，补齐三处响应头。
"""

import functools
import http.server
import socketserver
import urllib.parse


def zhizao_chuli(anquan=False):
    """生成请求处理类。anquan=True 时补齐安全响应头（修复版）。"""

    class ChuLi(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            name = qs.get("name", [""])[0]

            # 反射点：直接把用户输入拼进 HTML（未修复版，演示用，切勿用于真实服务）
            html = (
                "<!DOCTYPE html><html><head><meta charset='utf-8'>"
                "<title>本地靶场</title></head><body>"
                "<h1>本地靶场（%s）</h1>"
                "<p>你输入的名字：%s</p>"
                "<form method='get'><input name='name'/>"
                "<button>提交</button></form>"
                "</body></html>"
            ) % ("已修复版" if anquan else "未修复版", name)

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            if anquan:
                # 修复：补齐三处安全响应头
                self.send_header(
                    "Content-Security-Policy", "default-src 'self'")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("X-Content-Type-Options", "nosniff")
            # 未修复版：故意不发送上述任何头
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))

        def log_message(self, fmt, *args):
            # 关掉默认访问日志，避免刷屏
            pass

    return ChuLi


def qidong(port=8000, anquan=False):
    """启动靶场。默认绑定 127.0.0.1，确保只暴露在本机。"""
    chuli = zhizao_chuli(anquan)
    httpd = socketserver.TCPServer(("127.0.0.1", port), chuli)
    print("靶场已启动：http://127.0.0.1:%d （anquan=%s）" % (port, anquan))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    import sys
    duankou = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    qidong(duankou, False)
