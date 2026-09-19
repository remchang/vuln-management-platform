# -*- coding: utf-8 -*-
# 安装依赖脚本。
# 说明：本实验严禁安装 streamlit/pandas 之外的重包。这里只装 pytest。
# 网络慢，必须使用阿里云镜像。要跑界面请自行 pip install streamlit。
$py = "C:\Users\王锐兵\.workbuddy\binaries\python\versions\3.13.12\python.exe"
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$proj = Split-Path -Parent $root

# 1) 创建虚拟环境
& $py -m venv (Join-Path $proj ".venv")
$venvPy = Join-Path $proj ".venv\Scripts\python.exe"

# 2) 用阿里云镜像安装 pytest
& $venvPy -m pip install -i https://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com pytest

Write-Output "安装完成。核心逻辑用 pytest 验证；要跑 app.py 界面需自行 pip install streamlit。"

