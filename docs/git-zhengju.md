# 个人开发过程与 Git 证据对照表（实验07）

仓库：https://github.com/remchang/vuln-management-platform

---

## 一、Issue 与 Commit 对照

| Issue | 标题 | 阶段 | 关联 Commit |
| --- | --- | --- | --- |
| #1 | 授权范围与白名单门禁 | 基线 | `chore(baseline)` |
| #2 | 扫描报告解析与 HTML 净化 | 核心功能 | `feat(parse)` |
| #3 | 稳定指纹与跨扫描去重 | 自主功能 | `feat(fingerprint)` |
| #4 | 漏洞工作流与证据门禁 | 核心功能 | `feat(workflow)` |
| #5 | 复扫对比与覆盖度校验 | 自主功能 | `feat(compare)` |
| #6 | 修复与回归 | 核心功能 | `fix(target)` |
| #7 | 平台界面与报告脱敏 | 界面 | `feat(ui)` |
| #8 | 测试、证据与交付文档 | 测试 / 文档 | `test(tests)` / `docs` |

Issue 正文留档在 `docs/issue.md`。

## 二、Commit 一览

| # | 类型 | 覆盖阶段 | 主要内容 |
| --- | --- | --- | --- |
| 1 | `chore(baseline)` | 基线 | scope、白名单配置、报告夹具、依赖与许可证 |
| 2 | `feat(parse)` | 核心功能 | ZAP JSON 解析 + HTML 净化 |
| 3 | `feat(fingerprint)` | 自主功能 | 稳定指纹与规范化规则 |
| 4 | `feat(workflow)` | 核心功能 | SQLite 存储 + 7 状态 + 证据门禁 |
| 5 | `feat(compare)` | 自主功能 | 复扫四分类 + 覆盖度校验 |
| 6 | `fix(target)` | 核心功能 | 补齐三个安全响应头 |
| 7 | `feat(ui)` | 界面 | Streamlit 界面（首屏法律警告） |
| 8 | `test(tests)` | 测试 | 32 条 pytest |
| 9 | `docs` | 文档 | README、实验报告、人工复核、测试记录 |

覆盖实验要求的五类：**基线 / 核心功能 / 自主功能 / 测试 / 文档**。

## 三、分支与 PR

- 特性分支：`feature/finding-lifecycle`
- PR 关联 Issue #3 #5 #6，描述里附了 `pytest` 输出与夹具对比结果
- 合并前完成一次有文字记录的自我 Code Review（见下节）

## 四、自我 Code Review 检查清单

| # | 检查项 | 结论 |
| --- | --- | --- |
| 1 | 范围校验在扫描**之前**吗？ | ✅ 是。`shengcheng_saomiao_mingling()` 先校验，不过就抛异常 |
| 2 | 私网地址会自动放行吗？ | ✅ 不会。必须显式写进 `allowed_ips` |
| 3 | 重定向越界会被拦吗？ | ✅ 会，有独立函数与测试 |
| 4 | 有没有假设 alert 顶层有 url？ | ✅ 没有，从 instance 层取 |
| 5 | 多个 instance 会不会漏？ | ✅ 不会，按 instance 建 Finding，有测试 |
| 6 | 描述里的 HTML 净化了吗？ | ✅ 用 `qu_html` 转纯文本 |
| 7 | 指纹会不会误合并不同资源？ | ✅ 路径与参数名原样进指纹，有反例测试 |
| 8 | 随机查询值归一化了吗？ | ✅ 归一化了 |
| 9 | 重复导入会不会增殖？ | ✅ 不会，有测试 |
| 10 | 没有证据能不能改 Verified？ | ✅ 不能，代码级硬约束 + 测试 |
| 11 | 覆盖不足时会不会误判修复？ | ✅ 会给警告并拒绝 Verified |
| 12 | 风险等级变化有没有单独归类？ | ✅ 有，不会被当成"未变" |
| 13 | CSP 是不是照搬了最严策略？ | ✅ 没有，用 `default-src 'self'`，避免页面不可用 |
| 14 | HSTS 无脑加了吗？ | ✅ 没有。HTTP 场景下加了反而坏事，判为接受风险 |
| 15 | 报告里的凭据会被展示吗？ | ✅ 值会被换成 `***`，但保留结构以便复现 |
| 16 | 有没有伪造告警凑数？ | ✅ 没有，用了 9 条夹具告警，规则编号都是 ZAP 真实存在的 |
| 17 | 未实跑的部分说清楚了吗？ | ✅ scope / README / 报告 / 测试记录四处都写了 |

## 五、踩过的坑

1. **差点在 alert 层找 url**。
   ZAP 的 JSON 里 alert 层**没有** url，位置在 instance 层。
   如果按 alert 建记录，一个规则命中 5 个页面只会显示 1 条，另外 4 条永远没人管。

2. **CSP 差点照搬 `default-src 'none'`**。
   指导书明确警告过会导致业务不可用。本目标页面是纯静态无内联脚本，
   改用 `default-src 'self'`。

3. **HSTS 差点无脑修**。
   工具说"没设 HSTS，风险中"，但本目标是纯 HTTP 服务。
   加上 HSTS 会让浏览器强制升级到不存在的 https 地址，直接把演示搞坏。
   改成判为"接受风险"并记录理由。

4. **"复扫消失"不等于修复**。
   想通这一点之后才补了覆盖度校验。这是本次最有价值的收获。

5. **.gitignore 里 `data/` + `!data/README.md` 不生效**。
   Git 不会进入被忽略的目录，"!" 例外也就无从谈起。
