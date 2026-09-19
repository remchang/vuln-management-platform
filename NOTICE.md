# 第三方资源与许可证说明（NOTICE）

本仓库是《开源软件与新技术》课程实验07 的**二次开发成品**。
下面逐项列出用到的上游项目、来源、版本和许可证。

---

## 一、上游项目

| 项目 | 用途 | 固定版本 | 许可证 | 本次使用程度 |
| --- | --- | --- | --- | --- |
| [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) | HTTP 被动安全检测与报告生成 | **2.17.0** | Apache-2.0 | **未实装、未实跑**（本机无 ZAP） |
| [DefectDojo/django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo) | 完整漏洞管理平台（概念参考） | — | BSD-3-Clause | 仅阅读概念，**未部署** |
| [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | 教学靶场 | — | MIT | **未运行**（本实验的修复针对本人源码） |
| [streamlit/streamlit](https://github.com/streamlit/streamlit) | 平台界面框架 | — | Apache-2.0 | 代码已写，**本机未安装**（界面未实跑） |
| [pandas-dev/pandas](https://github.com/pandas-dev/pandas) | 数据处理 | 见 `requirements.txt` | BSD-3-Clause | 已实装并用于测试 |
| [pytest-dev/pytest](https://github.com/pytest-dev/pytest) | 测试框架 | 见 `requirements.txt` | MIT | 已实装，32 条测试实跑通过 |

## 二、上游提供的能力 vs 本人实现的部分

指导书明确要求"不能把 ZAP 导出的报告当成完整平台"，
也不能把上游能力写成本人成果。逐项区分如下：

| 能力 | 谁提供的 |
| --- | --- |
| HTTP 请求发送、被动规则引擎、告警生成 | **上游 ZAP**（本机未实跑） |
| Traditional JSON 报告的**格式定义** | **上游 ZAP** |
| Streamlit 的组件库与运行机制 | **上游 Streamlit** |
| 授权范围门禁（白名单、重定向校验、私网不自动授权） | **本人实现**（`platform/fanwei.py`） |
| ZAP JSON 解析器（含缺字段/空 site/多实例容错） | **本人实现**（`platform/zap_jiexi.py`） |
| HTML 净化（把扫描证据按纯文本展示） | **本人实现**（`platform/zap_jiexi.py`） |
| 稳定指纹算法与跨扫描去重 | **本人实现**（`platform/zhiwen.py`） |
| 漏洞工作流（7 状态 + 证据门禁） | **本人实现**（`platform/cunchu.py`） |
| 复扫对比（新增/未变/风险变化/已关闭 + 覆盖不足警告） | **本人实现**（`platform/duibi.py`） |
| 被测目标应用（含未修复版与修复版） | **本人编写**（`target/`） |
| ZAP 报告夹具 | **本人手工构造**（见下方第三节） |
| 界面（Scope 警告 → 导入 → 列表 → 状态编辑 → Dashboard） | **本人实现**（`app.py`） |
| 32 条测试 | **本人编写**（`tests/`） |

## 三、★ 关于 reports/ 里的两份 JSON

`reports/zap-before.json` 和 `reports/zap-after.json` 是
**人工构造的测试夹具，不是 OWASP ZAP 的真实输出**。

**为什么需要构造**：本机没有安装 Docker，也没有安装 ZAP，
无法产生真实报告。但"解析 → 指纹去重 → 状态流转 → 前后对比"
这套逻辑必须能被验证，否则整个平台的核心功能就是没测过的。

**构造依据**：严格按 ZAP 2.17.0 Traditional JSON 的真实结构编写——
`site[] -> alerts[] -> instances[]`，规则字段在 alert 层
（`pluginid` / `riskcode` / `name` / `desc` / `solution` / `cweid`），
具体位置在 instance 层（`uri` / `method` / `param` / `evidence`）。
用到的规则编号（10020 X-Frame-Options、10021 X-Content-Type-Options、
10038 CSP、10035 HSTS、10019 Content-Type、10049 Cache-Control 等）
都是 ZAP 真实存在的被动规则。

**夹具里没有编造规则编号，也没有把夹具结果说成真实扫描结果。**
这一点在 README、`scope.md`、实验报告和 `reports/README.md` 里都写明了。

## 四、被测目标

`target/app.py` 与 `target/app_yiuxiu.py` 是**本人编写的本地演示应用**，
只用 Python 标准库，不含任何第三方代码。

它们故意缺少安全响应头（CSP / X-Frame-Options / X-Content-Type-Options），
用来演示"修复 → 复扫 → 关闭"这个闭环。
**这不是漏洞利用工具**，只是一个用于演示修复流程的最小 HTTP 服务。

## 五、数据来源

- 所有告警内容（URL、参数、证据）都是**虚构的**，指向 `localhost:8000`。
- 不含任何真实系统的域名、参数或响应内容。
- 不含任何个人信息。

## 六、本仓库自己的许可证

**MIT**，见 [LICENSE](LICENSE)。并附带安全工具的额外声明
（只允许对自有或已授权目标使用）。

与上游许可证的兼容性：MIT 与 Apache-2.0（ZAP）、BSD-3-Clause（DefectDojo）、
MIT（Juice Shop、pytest）、Apache-2.0（Streamlit）**均兼容**。

## 七、关于 Apache-2.0 与 AGPL 的义务说明

- **ZAP 是 Apache-2.0**：本实验没有修改也没有重新分发其源码，
  只在本文件保留来源声明。若以后要改源码再分发，必须保留版权声明、
  标注修改过的文件、并附许可证副本。
- **如果本平台将来集成 AGPL 组件**（如某些 Grafana 版本），
  通过网络提供服务时**必须**保留许可证声明并履行源码提供义务。
  本实验未引入 AGPL 组件，此处仅作前瞻说明。
