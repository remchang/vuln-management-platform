# 实验07 · 软件安全检测与漏洞管理平台 —— Windows 辅助脚本（PowerShell 5.1）
# 真实 ZAP 调用脚本（示意）。
# 关键：无论原生 java 路线还是容器路线，都必须先通过 platform/fanwei.py
# 的授权门禁校验，校验不过就绝不生成/执行扫描命令。
# 本机没有 ZAP 也没有 Docker，所以下方命令只作示意，未实跑。
$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$proj = Split-Path -Parent $root
$venvPy = Join-Path $proj ".venv\Scripts\python.exe"

$url = $args[0]
if (-not $url) {
    Write-Output "用法：.\saomiao.ps1 <目标URL>"
    exit 1
}

# === 第一步：授权门禁校验（必须先过）===
& $venvPy -c @"
import importlib.util, os, sys
ROOT = r'$proj'
spec = importlib.util.spec_from_file_location('platform', os.path.join(ROOT, 'platform', '__init__.py'))
pkg = importlib.util.module_from_spec(spec); sys.modules['platform'] = pkg; spec.loader.exec_module(pkg)
from platform.fanwei import jiaoyan_mubiao, shengcheng_saomiao_mingling
jg = jiaoyan_mubiao('$url')
print('门禁校验结果：', jg)
if not jg['yuxu']:
    print('拒绝扫描：', jg['yuanyin'])
    sys.exit(2)
mingling = shengcheng_saomiao_mingling('$url')
print('校验通过，建议命令：')
print(mingling)
"@
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# === 路线一：原生 java -jar（需本地已安装 ZAP 与 JRE）===
# java -jar "%LOCALAPPDATA%\ZAP\ZAP_2.16.0\zap-2.16.0.jar" -cmd -quickurl $url -quickprogress
# 导出 Traditional JSON：
# java -jar zap.jar -cmd -quickurl $url -quickout zap-out.json

# === 路线二：容器 zap-baseline（需本机有 Docker）===
# docker run --rm -t zaproxy/zap-stable zap-baseline.py -t $url -J zap-out.json

Write-Output "提示：本机尚未安装 ZAP / Docker，以上命令仅供示意，未实跑。"

