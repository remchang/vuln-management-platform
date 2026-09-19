# -*- coding: utf-8 -*-
"""pytest 入口配置。

坑：本项目的核心包目录叫 `platform/`，而 Python 标准库自带一个同名模块
`platform.py`。直接 `import platform` 会被标准库抢走，导致
`from platform.fanwei import ...` 全部失败。这里用 importlib 显式把本地的
`platform/` 目录作为包加载并注册进 sys.modules，抢在标准库之前占住这个名字，
从而让相对导入（如 platform 内部的 `from .zhiwen import`）正常工作。
"""

import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

# 注意：pytest 启动时可能已经被标准库 import 过 `platform`，所以这里必须
# 无条件覆盖 sys.modules["platform"]，而不能用「不存在才注册」的判断。
PKG_DIR = os.path.join(ROOT, "platform")
spec = importlib.util.spec_from_file_location(
    "platform", os.path.join(PKG_DIR, "__init__.py")
)
pkg = importlib.util.module_from_spec(spec)
sys.modules["platform"] = pkg
spec.loader.exec_module(pkg)
