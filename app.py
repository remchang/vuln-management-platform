# -*- coding: utf-8 -*-
"""
漏洞管理平台界面（薄封装）。

设计原则：所有业务逻辑都在 platform/ 里，这里只是把逻辑“画”出来。
本机没有安装 Streamlit，因此本文件不会真正运行；要跑界面请自行：
    pip install streamlit
    python app.py
界面顶部第一屏必须是法律与范围警告，提醒使用者只扫自己有权限的目标。

如果 streamlit 没装，直接运行本文件会在控制台给出提示，不会报错崩溃。
"""

import os
import sys

# 让 platform / target 可被导入（同样要绕开标准库 platform 同名冲突）
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import importlib.util
if "platform" not in sys.modules or not hasattr(sys.modules["platform"], "fanwei"):
    _spec = importlib.util.spec_from_file_location(
        "platform", os.path.join(ROOT, "platform", "__init__.py")
    )
    _pkg = importlib.util.module_from_spec(_spec)
    sys.modules["platform"] = _pkg
    _spec.loader.exec_module(_pkg)

from platform import cunchu, duibi, zap_jiexi

DB_LUJING = os.path.join(ROOT, "vuln.db")
REPORT_DIR = os.path.join(ROOT, "reports")


def _shifou_you_streamlit():
    try:
        import streamlit  # noqa: F401
        return True
    except ImportError:
        return False


def _xianshi_fanwei_jinggao():
    """顶部第一屏：法律与范围警告。"""
    import streamlit as st
    st.warning(
        "法律与范围警告：本平台仅用于你已获得书面授权的目标（见 scope.md）。"
        "禁止对任何组织/个人的公网系统、未授权内网做任何扫描或请求。"
        "任何扫描前都会经过 platform/fanwei.py 的授权门禁校验，"
        "公网域名、重定向到非白名单主机、未显式授权的私网一律拒绝。"
    )


def zhu():
    if not _shifou_you_streamlit():
        print("未检测到 Streamlit，界面未启动。")
        print("核心逻辑请用 tests/ 验证：pytest -q")
        print("要运行界面：pip install streamlit 后 python app.py")
        return

    import streamlit as st

    _xianshi_fanwei_jinggao()

    st.title("软件安全检测与漏洞管理平台")

    # 侧边栏：选择操作
    caozuo = st.sidebar.selectbox(
        "功能", ["导入报告", "Finding 列表", "复扫对比", "Dashboard"]
    )

    ck = cunchu.Cunchu(DB_LUJING)

    if caozuo == "导入报告":
        wenjian = st.file_uploader("选择 ZAP Traditional JSON 报告", type=["json"])
        if wenjian:
            shuju = zap_jiexi.jiexi_shuju(__import__("json").loads(wenjian.read()))
            if st.button("导入"):
                pici = ck.chuangjian_pici(wenjian.name, "界面导入")
                ck.daoru_alerts(shuju, pici)
                st.success("已导入 %d 条发现，批次 %d" % (len(shuju), pici))

    elif caozuo == "Finding 列表":
        zhuangtai = st.selectbox("按状态筛选", ["全部"] + cunchu.ZHUANGTAI_YUNXU)
        fuzeren = st.text_input("按负责人筛选（可空）")
        liebiao = ck.liebiao_findings(
            zhuangtai=None if zhuangtai == "全部" else zhuangtai,
            fuzeren=fuzeren or None,
        )
        for f in liebiao:
            with st.expander("%s | %s | %s" % (f["guize_id"], f["name"], f["zhuangtai"])):
                st.write("指纹：", f["zhiwen"])
                st.write("风险：", f["riskcode"], " CWE：", f["cweid"])
                st.write("负责人：", f["fuzeren"] or "（未指派）")
                st.write("处置理由：", f["chuzhi_liyou"] or "（无）")
                xin_zt = st.selectbox(
                    "状态", cunchu.ZHUANGTAI_YUNXU,
                    index=cunchu.ZHUANGTAI_YUNXU.index(f["zhuangtai"]),
                    key=f["zhiwen"],
                )
                if st.button("保存状态", key="save_" + f["zhiwen"]):
                    ck.shezhi_zhuangtai(
                        f["zhiwen"], xin_zt,
                        xiufu_commit=f["xiufu_commit"] or None,
                        fusaomiao_pici=f["fusaomiao_pici"] or None,
                    )
                    st.success("已更新")

    elif caozuo == "复扫对比":
        qian = zap_jiexi.jiexi_lujing(os.path.join(REPORT_DIR, "zap-before.json"))
        hou = zap_jiexi.jiexi_lujing(os.path.join(REPORT_DIR, "zap-after.json"))
        jg = duibi.duibi_saomiao(qian, hou)
        st.subheader("复扫对比结果")
        st.write("新增：", len(jg["xinzeng"]))
        st.write("未变：", len(jg["weibian"]))
        st.write("风险变化：", len(jg["fengxian_bianhua"]))
        st.write("已关闭：", len(jg["yiguanbi"]))
        if jg["fugai_buzu"]:
            st.error("覆盖不足（覆盖率 %.2f），已关闭项只能保持 Resolved，不能判 Verified" % jg["fugai_zu"])

    elif caozuo == "Dashboard":
        st.subheader("状态分布")
        liebiao = ck.liebiao_findings()
        tongji = {}
        for f in liebiao:
            tongji[f["zhuangtai"]] = tongji.get(f["zhuangtai"], 0) + 1
        st.bar_chart(tongji)

    ck.guanbi()


if __name__ == "__main__":
    zhu()
