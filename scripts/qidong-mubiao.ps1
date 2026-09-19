# 实验07 · 软件安全检测与漏洞管理平台 —— Windows 辅助脚本（PowerShell 5.1）
# 启动本地被测靶场：未修复版（端口 8000）与修复版（端口 8001）。
# 两个版本业务代码相同，仅安全响应头不同，用于演示“修复—复扫”闭环。
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$proj = Split-Path -Parent $root
$venvPy = Join-Path $proj ".venv\Scripts\python.exe"

# 未修复版：缺 CSP / X-Frame-Options / X-Content-Type-Options
Start-Process -FilePath $venvPy -ArgumentList (Join-Path $proj "target\app.py"), "8000"

# 修复版：补齐上述三处安全头
Start-Process -FilePath $venvPy -ArgumentList (Join-Path $proj "target\app_yiuxiu.py"), "8001"

Write-Output "未修复版： http://127.0.0.1:8000"
Write-Output "修复版：   http://127.0.0.1:8001"
Write-Output "停止：在任务管理器结束 python 进程，或关闭对应窗口。"

