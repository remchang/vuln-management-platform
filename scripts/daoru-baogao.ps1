# 实验07 · 软件安全检测与漏洞管理平台 —— Windows 辅助脚本（PowerShell 5.1）
# 导入一份 ZAP 报告到本地 SQLite 库（vuln.db）。
# 用法：.\daoru-baogao.ps1 <报告路径> [数据库路径]
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$proj = Split-Path -Parent $root
$venvPy = Join-Path $proj ".venv\Scripts\python.exe"

$baogao = $args[0]
if (-not $baogao) {
    $baogao = Join-Path $proj "reports\zap-before.json"
}
$db = $args[1]
if (-not $db) {
    $db = Join-Path $proj "vuln.db"
}

& $venvPy -c @"
import importlib.util, os, sys
ROOT = r'$proj'
spec = importlib.util.spec_from_file_location('platform', os.path.join(ROOT, 'platform', '__init__.py'))
pkg = importlib.util.module_from_spec(spec); sys.modules['platform'] = pkg; spec.loader.exec_module(pkg)
from platform import zap_jiexi
from platform.cunchu import Cunchu
ck = Cunchu(r'$db')
pici = ck.chuangjian_pici(r'$baogao', '手动导入')
ck.daoru_alerts(zap_jiexi.jiexi_lujing(r'$baogao'), pici)
print('导入完成，当前 Finding 数：', ck.jishu_findings())
print('本批次 id：', pici)
"@

