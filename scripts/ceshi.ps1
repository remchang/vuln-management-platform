# -*- coding: utf-8 -*-
# 运行测试套件。
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$proj = Split-Path -Parent $root
$pytest = Join-Path $proj ".venv\Scripts\pytest.exe"
& $pytest -q (Join-Path $proj "tests")

