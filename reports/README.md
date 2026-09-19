# 关于 reports/ 目录里的文件

## 重要声明（请先读这一行）

本目录下的 `zap-before.json` 和 `zap-after.json` **是人工构造的测试夹具（fixture），
不是 ZAP 真实输出**。本机环境没有安装 ZAP，也没有 Docker，原生 Java 路线和
容器 `zap-baseline` 路线都 **没有实跑过**。这两份 JSON 仅仅是为了验证本平台的
“解析 / 指纹去重 / 复扫对比”逻辑而手工拼出的，其字段结构严格参照 ZAP
Traditional JSON 报告（`site[] -> alerts[] -> instances[]`）的真实形态。

真实 ZAP 报告的生成方式见 `../scripts/saomiao.ps1`，但运行前必须先通过
`platform/fanwei.py` 的授权门禁校验。

## 两份夹具的用途

- `zap-before.json`：模拟“修复前”的扫描结果。含 8 条 alert，其中 10020、
  10021 各有 2 个 instances，共 10 条发现。安全头缺失类告警（10020 / 10021 /
  10038）都在。
- `zap-after.json`：模拟“修复后复扫”的结果。10020 / 10021 / 10038 已消失，
  其余告警保留，并新增 1 条 10049。其中 10024 的风险等级从 Low 变为 Medium，
  用于演示“风险变化”分类。

用这两份夹具跑 `tests/`，可以验证：解析不漏实例、指纹去重、before→after 的
新增 / 未变 / 风险变化 / 已关闭 四类分类都正确。
