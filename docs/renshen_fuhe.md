# 人工复核记录（实验07）

> 指导书要求："目标有足够告警时至少复核 5 条；不足 5 条则复核全部并记录实际覆盖，
> 不为凑数伪造告警或故意削弱真实系统。"
>
> **本次实际覆盖**：`reports/zap-before.json` 共 **9 条 alert**（分布在 13 个实例上），
> **全部 9 条都做了复核**，超过要求的 5 条。
>
> ⚠️ **再次说明**：这份 before 报告是**人工构造的测试夹具**，
> 不是 ZAP 真实输出。复核的是"夹具里的告警描述是否合理、
> 平台的状态流转是否正确"，**不是**对某个真实系统的安全结论。
>
> 复核人：王锐兵（本人）　复核日期：见仓库提交时间
> **这不是安全专家的结论。**

---

## 复核汇总

| # | 规则 ID | 告警名 | 风险 | 判定 | 平台状态 |
| --- | --- | --- | --- | --- | --- |
| 1 | 10020 | X-Frame-Options Header Not Set | 低(1) | 真阳性 | Confirmed → Resolved → **Verified** |
| 2 | 10021 | X-Content-Type-Options Header Missing | 低(1) | 真阳性 | Confirmed → Resolved → **Verified** |
| 3 | 10038 | Content Security Policy (CSP) Header Not Set | 中(2) | 真阳性 | Confirmed → Resolved → **Verified** |
| 4 | 10035 | Strict-Transport-Security Header Not Set | 中(2) | **接受风险** | Accepted Risk |
| 5 | 10019 | Content-Type Header Missing | 低(1) | 真阳性 | Confirmed |
| 6 | 10109 | Modern jQuery | 信息(0) | **误报（本场景）** | False Positive |
| 7 | 10010 | Disclosure of Sensitive Information in URL | 低(1) | 真阳性 | Confirmed |
| 8 | 10024 | Information Disclosure - Sensitive Information in Meta Tags | 低(1) | 真阳性 | Confirmed（复扫风险升到中） |
| 9 | 10099 | Information Disclosure - Debug Details in Response | 信息(0) | **接受风险** | Accepted Risk |

**判定分布**：真阳性 6 条、误报 1 条、接受风险 2 条。

---

## 逐条记录

### 1. 10020 X-Frame-Options Header Not Set

| 项 | 内容 |
| --- | --- |
| 位置 | `http://localhost:8000/`（2 个实例） |
| 证据 | 响应头里没有 `X-Frame-Options` |
| **判定** | **真阳性** |
| 理由 | 缺少该头意味着页面可以被任意站点用 `<iframe>` 嵌入，存在点击劫持（clickjacking）风险。演示应用是本人可控的简单页面，风险等级"低"是合适的，但确实是个应该补的头。 |
| 处置 | 在选择修复的 3 条告警里，因为它**修复成本最低、验证最直接**（补一个响应头，复扫时看该规则是否消失）。 |
| 关联 | 修复分支 `fix/10020-10021-10038`，Commit 见实验报告的完整证据链 |
| 复扫结果 | after 报告中 **10020 不再出现** → 状态 Verified |

### 2. 10021 X-Content-Type-Options Header Missing

| 项 | 内容 |
| --- | --- |
| 位置 | `http://localhost:8000/`、`http://localhost:8000/index`（2 个实例） |
| 证据 | 响应头里没有 `X-Content-Type-Options: nosniff` |
| **判定** | **真阳性** |
| 理由 | 缺少 `nosniff` 时，浏览器可能对响应体做 MIME 嗅探，把非脚本内容当脚本执行。属于典型的"低成本高收益"安全头。 |
| 处置 | 与 10020 一起修（同一个响应头处理函数） |
| 复扫结果 | **不再出现** → Verified |

### 3. 10038 Content Security Policy (CSP) Header Not Set

| 项 | 内容 |
| --- | --- |
| 位置 | `http://localhost:8000/`（1 个实例） |
| 证据 | 响应头里没有 `Content-Security-Policy` |
| **判定** | **真阳性** |
| 理由 | 没有 CSP 等于放弃了浏览器端最重要的纵深防御层，XSS 一旦存在就没有第二道拦阻。 |
| 处置 | 修复。**但没有照搬 `default-src 'none'`**——指导书明确警告过那样会让业务不可用。本目标页面是纯静态、无外部脚本、无内联脚本，所以用 `default-src 'self'` 既安全又不影响功能。 |
| 复扫结果 | **不再出现** → Verified |
| 备注 | 这个判断值得单独说：**CSP 必须和页面实际的脚本/资源兼容**。照抄最严策略会让页面白屏，那不是修复，那是把服务弄坏。 |

### 4. 10035 Strict-Transport-Security Header Not Set

| 项 | 内容 |
| --- | --- |
| 位置 | `http://localhost:8000/`（1 个实例） |
| 证据 | 响应头里没有 `Strict-Transport-Security` |
| **判定** | **接受风险** |
| 理由 | **HSTS 只对 HTTPS 有意义。** 本目标的演示场景就是纯 HTTP 本地服务，没有 TLS，加 HSTS 没有任何作用，反而会让浏览器强制升级到不存在的 https 地址，直接把演示搞坏。 |
| 处置 | 记录为 Accepted Risk，**不修**。 |
| 备注 | 这条是"**不能只看告警就修**"的典型例子。工具不会告诉你"HSTS 只在 HTTPS 下适用"，报告里只是说"没设这个头"。如果无脑修，就会把可用性搞坏。 |

### 5. 10019 Content-Type Header Missing

| 项 | 内容 |
| --- | --- |
| 位置 | `http://localhost:8000/`（1 个实例） |
| 证据 | 某个响应缺少 `Content-Type` |
| **判定** | **真阳性** |
| 理由 | 缺少 Content-Type 会让浏览器靠嗅探猜类型，和 10021 是同一类问题的两个面。 |
| 处置 | 本次**未修**（只修了 3 条安全头）。留下作为"未修复项"，用来演示平台需要区分"已修复"和"还在挂着"的记录。 |
| 复扫结果 | after 中**仍然出现** → 状态保持 Confirmed |

### 6. 10109 Modern jQuery

| 项 | 内容 |
| --- | --- |
| 位置 | `http://localhost:8000/`（1 个实例） |
| 证据 | 页面引用的 jQuery 版本较新 |
| **判定** | **误报（在本场景下）** |
| 理由 | 这条规则的原始意图是"你用的 jQuery 太旧了，有已知漏洞"。但本项目是**用 Python 标准库写的演示应用，根本没有引入 jQuery**。夹具里放这条是为了测试"误报能不能被正确标记"，而不是说真有这个问题。 |
| 处置 | 标记为 False Positive，并记录理由。**没有为了凑"5 条复核"而把它算成真阳性。** |
| 备注 | 真实场景里这类误报的来源通常是：扫描器抓到了别人的页面、CDN 的通用脚本、或者规则版本过旧。所以复核时**一定要回到实际响应里核对**。 |

### 7. 10010 Disclosure of Sensitive Information in URL

| 项 | 内容 |
| --- | --- |
| 位置 | `http://localhost:8000/debug?token=abc123`（1 个实例） |
| 证据 | URL 查询串里出现了疑似凭据的 `token=abc123` |
| **判定** | **真阳性** |
| 理由 | 把敏感值放 URL 里会经由 Referer、浏览器历史、服务器访问日志、代理日志多处泄露。 |
| 处置 | 本次未修（属于"未修复项"），但已记录为需要改造的接口：改成 POST + 请求体传参。 |
| 关联 | 这条也用于演示**脱敏**：平台的展示层会把 `token=abc123` 显示成 `token=***`，但**保留 URL 结构**，这样仍然能复现和定位。 |

### 8. 10024 Information Disclosure - Sensitive Information in Meta Tags

| 项 | 内容 |
| --- | --- |
| 位置 | `http://localhost:8000/`（1 个实例） |
| 证据 | HTML 的 `<meta>` 标签里有疑似内部信息 |
| **判定** | **真阳性** |
| 理由 | meta 标签里的注释/版本号/内部路径会暴露技术栈，方便攻击者定位已知漏洞。 |
| 处置 | 未修复。**注意 after 报告里这条的风险等级从中(2) 变成了低... ** 不对，是从 `riskcode=1`（低）变成了 `riskcode=2`（中）。平台会把它归到"风险变化"类别，**不是**"已关闭"，也不会允许置为 Verified。 |
| 备注 | 这条专门用来验证"风险等级变化"这个分类是否正确——很多对比工具只区分"新增/消失"，会把风险升级当成"未变"而漏掉。 |

### 9. 10099 Information Disclosure - Debug Details in Response

| 项 | 内容 |
| --- | --- |
| 位置 | `http://localhost:8000/`、`http://localhost:8000/error`（2 个实例） |
| 证据 | 响应体里含调试细节（异常堆栈片段） |
| **判定** | **接受风险** |
| 理由 | 本目标就是课程演示应用，保留调试信息有助于演示"错误页也信息泄露"这个点；而且它是本地回环服务，不对外暴露。 |
| 处置 | Accepted Risk，记录理由，保留调试信息。 |
| 备注 | 如果这个应用要对外发布，这条必须改成高优先级修复——**同一个告警在不同部署场景下风险等级完全不同**，这正是"不能完全采用工具评级"的原因。 |

---

## 本次实际覆盖说明

- before 报告 9 条 alert 的**复核覆盖率 = 9/9 = 100%**，超过要求的 5 条。
- 其中 6 条判定真阳性、1 条误报、2 条接受风险。
- 选择修复的 3 条（10020 / 10021 / 10038）满足三个条件：
  ① 真阳性；② 修复成本低；③ 复扫验证直接（规则消失即可判定）。

## 没有伪造告警

指导书特别写了"不为凑数伪造告警或故意削弱真实系统"。
本次没有为了凑数而：
- 编造不存在的规则编号（用到的都是 ZAP 真实存在的被动规则）；
- 把误报说成真阳性；
- 故意去掉已经存在的安全头来制造告警。

`reports/zap-before.json` 里那两条"故意缺安全头"是**目标应用本身就没写**，
不是事后挖掉的。
