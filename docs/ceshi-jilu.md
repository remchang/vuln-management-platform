# 测试记录（实验07）

> 环境：Windows，Python 3.13.14。**没有 Docker，没有 ZAP。**
> 所有命令在项目根目录执行。

---

## 一、自动化测试（实测 ✅ 32 条）

```powershell
.\.venv\Scripts\python -m pytest tests -q
```

**实际输出：**

```
................................                                 [100%]
32 passed in 2.90s
```

### 分布与对照

| 文件 | 条数 | 实验要求 | 达标 |
| --- | --- | --- | --- |
| `tests/test_fanwei.py` | 7 | 范围安全测试 ≥6 | ✅ |
| `tests/test_jiexi_zhiwen.py` | 10 | 解析/去重测试 ≥8 | ✅ |
| `tests/test_cunchu.py` | 7 | 工作流测试 ≥6 | ✅ |
| `tests/test_xiufu.py` | 5 | 修复回归测试 ≥3 | ✅ |
| `tests/test_duibi.py` | 3 | 复扫比较 ≥2 | ✅ |
| **合计** | **32** | | |

### 全部用例清单

**范围安全测试**（`test_fanwei.py`）
- `test_baimingdan_nei_tongguo` —— 白名单内主机通过
- `test_baimingdan_ip_tongguo` —— 白名单 IP 通过
- `test_gongwang_yuju_jujue` —— 公网域名拒绝
- `test_zhongdingxiang_feibaimingdan_beilan` —— 重定向到白名单外被拦
- `test_feifa_url_jujue` —— 非法 URL 拒绝
- `test_siwang_weishouquan_jujue` —— 私网未显式授权拒绝
- `test_mingling_bixu_guoyan` —— 扫描命令必须过校验

**解析/去重测试**（`test_jiexi_zhiwen.py`）
- `test_jiexi_beisai_tiaoshu` —— 告警条数正确
- `test_duo_shili_bu_lou` —— 一个 alert 的多个 instance 都不漏
- `test_qu_html_wu_biaoqian` —— HTML 净化后无标签
- `test_que_ziduan_bu_bengkui` —— 缺字段不崩
- `test_kong_site` —— 空 site 返回空
- `test_ziduan_leixing_yichang` —— 字段类型异常不崩
- `test_suiji_chaxun_guifan` —— 随机查询值归一化
- `test_lujing_canshu_qufen` —— 路径/参数不被误合并
- `test_chongfu_daoru_bu_zengzhi` —— 重复导入不新增
- `test_pici_lishi_baoliu` —— 批次出现历史保留

**工作流测试**（`test_cunchu.py`）
- `test_zhuangtai_liuru` —— 状态流转
- `test_fuzeren_bixu` —— 负责人必填
- `test_chuzhi_liyou_bixu` —— 处置理由必填
- `test_zhuangtai_fanwei` —— 状态取值合法
- `test_meiyou_zhengju_buneng_verified` —— **无证据不能 Verified**
- `test_you_zhengju_ke_verified` —— 有证据可以 Verified
- `test_an_zhuangtai_chaxun` —— 按状态查询

**修复回归测试**（`test_xiufu.py`）
- `test_xiufu_x_frame` —— 修复版有 `X-Frame-Options`
- `test_xiufu_csp` —— 修复版有 CSP
- `test_xiufu_x_content_type` —— 修复版有 `X-Content-Type-Options`
- `test_weixiufu_que_tou` —— 未修复版确实缺这三个头
- `test_gongneng_bu_tuihua` —— 修复后原功能不退化

**复扫比较**（`test_duibi.py`）
- `test_fenlei_zhengque` —— 新增/未变/已关闭分类正确
- `test_fengxian_bianhua_neirong` —— 风险等级变化被单独归类
- `test_fugai_buzu_buneng_verified` —— 覆盖不足时拒绝判定修复

---

## 二、夹具对比的实际结果

```
before: 9 条 alert / 13 个 instance
after:  7 条 alert
```

| 分类 | 数量 | 具体 |
| --- | --- | --- |
| **已关闭** | 3 | `10020` X-Frame-Options、`10021` X-Content-Type-Options、`10038` CSP |
| **未变** | 5 | `10035`、`10019`、`10109`、`10010`、`10099` |
| **风险变化** | 1 | `10024`（riskcode 1 → 2，低 → 中） |
| **新增** | 1 | `10049` Cache-Control Header Not Set |

核对：before 9 − 已关闭 3 = 6，加新增 1 = **after 7** ✅

**为什么专门放一条"风险变化"**：很多对比工具只分"新增/消失"，
风险从低升到中会被算成"未变"而漏掉。这条就是用来验证分类正确性的。

---

## 三、★ 未实跑的部分（重要）

### 3.1 没有执行过任何真实 ZAP 扫描

| 项 | 状态 |
| --- | --- |
| 下载 ZAP 2.17.0 | ❌ 未执行 |
| 启动 ZAP daemon | ❌ 未执行 |
| 被动扫描（pscan） | ❌ 未执行 |
| 生成真实 JSON/HTML 报告 | ❌ 未执行 |
| 容器基线扫描 | ❌ 未执行（本机无 Docker） |

**原因**：本机没有安装 Docker（`docker --version` 无输出），
也没有安装 OWASP ZAP。指导书给出的两条路线（原生 Java 与容器）
都需要先下载安装工具，本机均未具备。

### 3.2 `reports/` 下的两份 JSON 是人工构造的夹具

- 严格按 ZAP **Traditional JSON** 的真实结构编写：
  `site[] -> alerts[] -> instances[]`
- 规则字段放在 alert 层（`pluginid` / `riskcode` / `name` / `desc` /
  `solution` / `cweid`），具体位置放在 instance 层
  （`uri` / `method` / `param` / `evidence`）
- 用到的规则编号（10020 / 10021 / 10038 / 10035 / 10019 / 10049 /
  10109 / 10010 / 10024 / 10099）**都是 ZAP 真实存在的被动规则**
- **但没有编造规则编号，也没有把夹具结果说成真实扫描结果**

`reports/README.md`、`scope.md`、`README.md`、`docs/实验报告.md`
四处都写明了这一点。

### 3.3 界面未实跑

Streamlit 本机未安装（依赖下载较大）。`app.py` 里做了优雅降级：

```python
def _shifou_you_streamlit():
    try:
        import streamlit  # noqa: F401
        return True
    except ImportError:
        return False
```

无 Streamlit 时会给出安装提示，而不是抛堆栈。
**但界面本身没有实际渲染验证过。**

### 3.4 已实测的部分

- **32 条测试全部实跑通过**（2.90 秒）
- 范围门禁的 6 条规则、重定向校验、命令生成前置校验都是真实执行的代码路径
- 指纹归一化与去重是真实执行的
- 状态门禁（无证据不能 Verified）是真实执行的
- 复扫对比的四个分类是真实执行的
- **被测目标应用是真实可运行的本地 HTTP 服务**，
  未修复版与修复版的响应头差异由测试真实断言

---

## 四、复现步骤

```powershell
git clone https://github.com/remchang/vuln-management-platform
cd vuln-management-platform
.\scripts\anzhuang.ps1            # 建 venv + 装依赖 + 跑测试
.\scripts\ceshi.ps1               # 只跑测试
.\scripts\qidong-mubiao.ps1       # 起未修复版目标（另开窗口）
.\scripts\qidong-mubiao.ps1 -AnquanBan   # 起修复版目标（对比用）
```

查看目标响应头差异：

```powershell
# 未修复版
(Invoke-WebRequest http://127.0.0.1:8000/).Headers | Format-List

# 修复版（另一个端口或先停掉未修复版）
(Invoke-WebRequest http://127.0.0.1:8000/).Headers | Format-List
```

---

## 五、测试证据清单（对照实验要求）

| 要求的证据 | 在哪 |
| --- | --- |
| 授权 scope 和扫描命令/镜像摘要 | `scope.md`、`platform/fanwei-peizhi.json`、README 第六节 |
| before/after 报告哈希及覆盖范围 | 导入时记录 SHA256；覆盖度由 `duibi.py` 对比并输出警告 |
| 5 条或本次全部告警的人工复核记录 | `docs/renshen_fuhe.md`（**9/9 条全复核**） |
| 至少一条漏洞到 PR、测试和复扫的完整链 | `docs/实验报告.md` 第五节（10020 的 10 步链路） |
| 可重复执行的测试命令 | `pytest -q` → 32 passed in 2.90s |
| 未实跑部分的边界说明 | 本文件第三节 + README 第九节 |
