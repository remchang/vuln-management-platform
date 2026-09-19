# 实验07 · 软件安全检测与漏洞管理平台 —— Windows 辅助脚本（PowerShell 5.1）
# 运行测试套件。
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$proj = Split-Path -Parent $root
$pytest = Join-Path $proj ".venv\Scripts\pytest.exe"
& $pytest -q (Join-Path $proj "tests")

