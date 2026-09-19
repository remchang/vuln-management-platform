# Issue 清单（实验07）

> 仓库 Issue 正文留档。

---

## Issue #1 授权范围与白名单门禁

**标签**：`安全边界`

### 用户价值

合法性是安全实验的前置条件。范围校验必须发生在**扫描之前**，
而且不能只靠"我保证不扫公网"这种口头承诺——要写进代码里强制校验。

### 实现要点

- `scope.md`：资产所有者、批准人、目标、允许时间、禁止动作、联系人
- `platform/fanwei-peizhi.json`：生效白名单（hosts / ips / urls / 禁用关键词）
- `jiaoyan_mubiao(url)`：6 条规则
- `jiaoyan_zhongdingxiang()`：重定向越界即停
- `shengcheng_saomiao_mingling()`：**必须过校验才返回命令**

### 关键决策

**私网地址不自动视为已授权。** `192.168.x.x` / `10.x.x.x` 必须显式写进
`allowed_ips`。指导书原文："不得把 RFC1918 私网自动视为已授权。"

### 验收条件

- [x] 白名单内通过（host 与 ip 两种形式）
- [x] 公网域名拒绝
- [x] 私网未显式授权拒绝
- [x] 非法 URL 拒绝
- [x] 重定向到白名单外被拦
- [x] 命令生成必须过校验
- [x] 拒绝时记录原因与命中规则

---

## Issue #2 扫描报告解析与 HTML 净化

**标签**：`核心功能`

### 要做什么

固定解析 ZAP **Traditional JSON** 格式，并且**容错**。

### 结构（实测夹具验证）

```
site[] -> alerts[] -> instances[]

alert 层字段：pluginid / riskcode / name / desc / solution / cweid
instance 层字段：uri / method / param / evidence
```

### ★ 最容易漏的一点

**不能假设每条 alert 顶层有 url**，具体位置在 instance 层。
一条 alert 可以命中多个 URL。

### HTML 净化

`desc` / `solution` 含 HTML，**必须净化后按纯文本展示**——
否则就是把扫描证据当可信 HTML 执行。

### 验收条件

- [x] 正常解析，告警条数正确
- [x] 多实例不漏（一个 alert 的 2 个 instance 都建记录）
- [x] `qu_html` 输出无标签
- [x] 缺字段不崩
- [x] 空 site 返回空列表
- [x] 字段类型异常不崩

---

## Issue #3 稳定指纹与跨扫描去重

**标签**：`自主功能`（本实验的自主扩展核心）

### 用户价值

同一份报告导入两次，不能让 Finding 翻倍；
两份报告对比时，要能判断"这条是新增还是老问题"。

### 指纹设计

```
指纹 = SHA256( 规则ID | 规范化origin | HTTP方法 | 规范化路径 | 规范化参数 )
```

| 归一化 | 做不做 | 理由 |
| --- | --- | --- |
| 随机查询值（`_=`、`cachebuster`） | ✅ | 只影响缓存 |
| 参数顺序 | ✅ | 等价请求 |
| 路径里的数字 ID | ❌ | `/item/1` ≠ `/item/2` |
| 参数名 | ❌ | `?id=` ≠ `?uid=` |

### 三个反例（测试里都有对应用例）

| 反例 | 错在哪 |
| --- | --- |
| `POST /api/user?id=1` vs `GET /api/user?id=1` | 方法不同是不同端点 → 方法进指纹 |
| `/item/1001` vs `/item/1002` | 路径资源 ID 不同 → 路径原样进指纹 |
| `?id=1` vs `?uid=1` | 参数名语义可能不同 → 参数名进指纹 |

### 验收条件

- [x] 随机查询值归一化（同一指纹）
- [x] 路径参数**不能**误合并
- [x] 参数名**不能**误合并
- [x] 重复导入不新增 Finding
- [x] 批次出现历史保留

---

## Issue #4 漏洞工作流与证据门禁

**标签**：`核心功能`

### 状态定义

`New` / `Confirmed` / `False Positive` / `Accepted Risk` /
`In Progress` / `Resolved` / `Verified`

### ★ 硬约束

**只有 Verified 表示复扫不再出现或经人工验证关闭。**
没有修复 Commit 且没有复扫批次记录时，**不允许**置为 Verified——
这是代码里的断言，不是流程文档里的建议。

```python
if zhuangtai == "Verified" and not (xiufu_commit or fusaopici):
    raise CunchuCuowu("没有修复证据，不允许置为 Verified")
```

### 必须记录的字段

负责人、风险等级、CWE、首次/最近发现时间、修复分支、Commit、
处置理由、复扫批次。

### 验收条件

- [x] 状态流转合法（不能从 New 直接到 Verified）
- [x] 负责人必填
- [x] 处置理由必填
- [x] 无证据不能 Verified
- [x] 有证据可以 Verified
- [x] 按状态查询

---

## Issue #5 复扫对比与覆盖度校验

**标签**：`自主功能`

### 用户价值

不只区分"新增/消失"，还要区分**风险等级变化**；并且要能识别
"页面没被爬到导致的假关闭"。

### 四个分类

| 类别 | 判定 |
| --- | --- |
| 新增 | 只在 after 出现 |
| 未变 | 两边都有，风险等级相同 |
| 风险变化 | 两边都有，riskcode 不同 |
| 已关闭 | 只在 before 出现 |

### ★ 覆盖度校验

```python
if len(hou_urls) < len(qian_urls) * 0.8:
    return {"jinggao": "覆盖不足，不能判定修复。状态只能保持 Resolved。"}
```

这是本实验里最有工程价值的一个设计：
**页面没被爬到 → 告警消失 → 看起来修好了 → 实际问题还在。**

### 验收条件

- [x] 四个分类判定正确
- [x] 风险等级变化被单独归类（不能算成"未变"）
- [x] 覆盖不足时给出警告且拒绝 Verified

---

## Issue #6 修复与回归

**标签**：`核心功能`

### 修复内容

三条安全响应头（都在同一个处理函数里，一起修）：

```python
tou["X-Frame-Options"] = "DENY"
tou["X-Content-Type-Options"] = "nosniff"
tou["Content-Security-Policy"] = "default-src 'self'"
```

### ★ 关于 CSP 的判断

**没有照搬 `default-src 'none'`。** 指导书明确警告过：

> CSP 应与页面脚本和资源兼容，不能照搬 default-src 'none' 导致业务不可用。

本目标页面是纯静态、无外部脚本、无内联脚本，
所以 `default-src 'self'` 既安全又不影响功能。
照抄最严策略只会让页面白屏 —— 那是把服务弄坏，不是修复。

### 验收条件

- [x] 修复版补齐三个头（3 条测试）
- [x] 未修复版确实缺这三个头
- [x] 修复后原功能不退化（返回 200 + 内容正确）

---

## Issue #7 平台界面与报告脱敏

**标签**：`界面` `安全`

### 界面设计

**第一屏必须是法律与范围警告。** 然后是导入 → 列表/筛选 →
状态与负责人编辑 → Dashboard → before/after 对比。

### 脱敏

| 项 | 做法 |
| --- | --- |
| Token / Cookie 值 | 展示前替换为 `***` |
| URL 结构 | **保留**（否则无法复现） |
| 参数名 | **保留**（否则无法判断是否同一问题） |
| 报告文件 | 记录 SHA256，便于核对用的是哪一份 |

### 验收条件

- [x] 首屏警告（`_xianshi_fanwei_jinggao()`）
- [x] 无 Streamlit 时优雅提示而不是崩溃
- [x] 报告目录限制访问说明写在 README

---

## Issue #8 测试、证据与交付文档

**标签**：`测试` `文档`

### 交付

- [x] 32 条 pytest（范围 7 / 解析去重 10 / 工作流 7 / 修复 5 / 对比 3）
- [x] `docs/renshen_fuhe.md`：**9 条告警全部复核**（要求 ≥5）
- [x] `scope.md` 授权记录
- [x] `NOTICE.md`：上游能力与本人实现的逐项对照
- [x] 一条漏洞从 before → 复核 → PR → 测试 → after → Verified 的完整证据链
- [x] 一键脚本：安装 / 起目标 / 扫描 / 导入 / 测试

### 已知缺口

- **本机没有 ZAP 也没有 Docker**，未执行任何真实扫描
- `reports/` 下是**人工构造的夹具**，不是真实扫描结果
- Streamlit 未安装，界面未实跑

以上都在 README 与测试记录里如实标明。
