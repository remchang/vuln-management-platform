# -*- coding: utf-8 -*-
"""
修复后的靶场应用。

做法：直接复用 target/app.py 的 qidong()，把 anquan 开关打开，补齐
CSP / X-Frame-Options / X-Content-Type-Options 三处安全响应头。
这样同一份业务代码，修复前（app.py）与修复后（本文件）只有响应头不同，
便于演示“修复—复扫”后 10020 / 10021 / 10038 告警消失。

运行：
    python target/app_yiuxiu.py
"""

from app import qidong


if __name__ == "__main__":
    import sys
    # 端口默认 8000；如需与未修复版并存，可传不同端口（如 8001）
    duankou = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    qidong(duankou, True)
