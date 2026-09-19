# -*- coding: utf-8 -*-
"""
漏洞存储与工作流模块（基于 SQLite，零额外依赖）。

状态机（至少包含以下状态）：
    New            新发现，尚未人工确认
    Confirmed      人工确认为真阳性
    False Positive 人工判定为误报
    Accepted Risk  风险接受（明知有洞但不修，需写理由）
    In Progress    修复中
    Resolved       已修复，等待复扫或验证
    Verified       已验证关闭（复扫不再出现，或人工验证关闭）

硬规则（写进代码并测试）：
    只有 Verified 表示“真的关掉了”。把一条 Finding 置为 Verified 必须同时具备：
      1) 修复 Commit（xiufu_commit 非空）；
      2) 复扫批次证据（fusaomiao_pici 非空，即复扫后该指纹不再出现）。
    缺任何一样都不允许置 Verified，用断言抛出，防止“嘴上说修好了”。

为什么要这些表：
    - findings：每条发现的当前状态，指纹做主键，天然去重。
    - saomiao_pici：每次导入是一个批次，记录来源和时间。
    - finding_chuchang：出现历史。重复导入同一份报告不会新建 Finding，
      但会在 chuchang 里累加“本次批次又出现了”的记录，便于追溯。
"""

import os
import sqlite3
from datetime import datetime

from .zhiwen import jisuan_zhiwen

# 允许的状态集合，状态流转时对值做校验，避免脏数据
ZHUANGTAI_YUNXU = [
    "New", "Confirmed", "False Positive", "Accepted Risk",
    "In Progress", "Resolved", "Verified",
]


def _xianzai():
    return datetime.now().isoformat(timespec="seconds")


class Cunchu:
    """漏洞仓储。默认使用内存库，便于测试；可传 db_lujing 落地到文件。"""

    def __init__(self, db_lujing=":memory:"):
        self.db_lujing = db_lujing
        self.conn = sqlite3.connect(db_lujing)
        self.conn.row_factory = sqlite3.Row
        self._chuangjian_biao()

    def _chuangjian_biao(self):
        c = self.conn.cursor()
        c.execute(
            """CREATE TABLE IF NOT EXISTS findings (
                zhiwen TEXT PRIMARY KEY,
                guize_id TEXT,
                riskcode TEXT,
                name TEXT,
                desc TEXT,
                solution TEXT,
                cweid TEXT,
                diyici_shijian TEXT,
                zuijin_shijian TEXT,
                fuzeren TEXT,
                zhuangtai TEXT,
                chuzhi_liyou TEXT,
                xiufu_fenzhi TEXT,
                xiufu_commit TEXT,
                fusaomiao_pici TEXT
            )"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS saomiao_pici (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                shijian TEXT,
                laiyuan TEXT,
                beizhu TEXT
            )"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS finding_chuchang (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                zhiwen TEXT,
                pici_id INTEGER,
                uri TEXT,
                method TEXT,
                param TEXT,
                chuxian_shijian TEXT
            )"""
        )
        self.conn.commit()

    # ---------- 批次 ----------
    def chuangjian_pici(self, laiyuan, beizhu=""):
        """登记一次扫描批次，返回批次 id。"""
        c = self.conn.cursor()
        c.execute(
            "INSERT INTO saomiao_pici (shijian, laiyuan, beizhu) VALUES (?, ?, ?)",
            (_xianzai(), laiyuan, beizhu),
        )
        self.conn.commit()
        return c.lastrowid

    # ---------- 导入告警 ----------
    def daoru_alerts(self, alerts, pici_id, xianzai=None):
        """把解析后的告警列表导入。

        - 指纹不存在 → 新建 Finding（状态 New）。
        - 指纹已存在 → 不重复创建，只更新最近发现时间和描述类字段。
        - 每条告警都在 chuchang 记一笔“本批次出现”，重复导入会累加批次记录，
          但 Finding 数量不增殖。
        """
        xianzai = xianzai or _xianzai()
        c = self.conn.cursor()
        for a in alerts:
            zhiwen = jisuan_zhiwen(
                a.get("guize_id", ""), a.get("uri", ""),
                a.get("method", "GET"), a.get("param", ""),
            )
            exists = c.execute(
                "SELECT 1 FROM findings WHERE zhiwen=?", (zhiwen,)
            ).fetchone()
            if not exists:
                c.execute(
                    """INSERT INTO findings
                       (zhiwen, guize_id, riskcode, name, desc, solution, cweid,
                        diyici_shijian, zuijin_shijian, fuzeren, zhuangtai)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (zhiwen, a.get("guize_id", ""), a.get("riskcode", ""),
                     a.get("name", ""), a.get("desc", ""), a.get("solution", ""),
                     a.get("cweid", ""), xianzai, xianzai, "", "New"),
                )
            else:
                # 已存在：刷新信息，但绝不改状态/负责人/处置理由，避免覆盖人工结论
                c.execute(
                    """UPDATE findings SET
                          zuijin_shijian=?, name=?, desc=?, solution=?,
                          riskcode=?, cweid=?
                       WHERE zhiwen=?""",
                    (xianzai, a.get("name", ""), a.get("desc", ""),
                     a.get("solution", ""), a.get("riskcode", ""),
                     a.get("cweid", ""), zhiwen),
                )
            # 出现历史始终记录（即便同一批次重复 instance 也允许，但这里每条告警记一笔）
            c.execute(
                """INSERT INTO finding_chuchang
                   (zhiwen, pici_id, uri, method, param, chuxian_shijian)
                   VALUES (?,?,?,?,?,?)""",
                (zhiwen, pici_id, a.get("uri", ""), a.get("method", "GET"),
                 a.get("param", ""), xianzai),
            )
        self.conn.commit()

    # ---------- 查询 ----------
    def huoqu_finding(self, zhiwen):
        c = self.conn.cursor()
        row = c.execute(
            "SELECT * FROM findings WHERE zhiwen=?", (zhiwen,)
        ).fetchone()
        return dict(row) if row else None

    def liebiao_findings(self, zhuangtai=None, fuzeren=None):
        c = self.conn.cursor()
        sql = "SELECT * FROM findings WHERE 1=1"
        args = []
        if zhuangtai:
            sql += " AND zhuangtai=?"
            args.append(zhuangtai)
        if fuzeren:
            sql += " AND fuzeren=?"
            args.append(fuzeren)
        sql += " ORDER BY zuijin_shijian DESC"
        rows = c.execute(sql, args).fetchall()
        return [dict(r) for r in rows]

    def jishu_findings(self):
        c = self.conn.cursor()
        return c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

    def chuchang_jilu(self, zhiwen):
        c = self.conn.cursor()
        rows = c.execute(
            "SELECT * FROM finding_chuchang WHERE zhiwen=? ORDER BY id",
            (zhiwen,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ---------- 工作流变更 ----------
    def shezhi_zhuangtai(self, zhiwen, zhuangtai, xiufu_commit=None,
                         fusaomiao_pici=None):
        """变更状态。Verified 有硬约束。"""
        if zhuangtai not in ZHUANGTAI_YUNXU:
            raise ValueError("非法状态：" + str(zhuangtai))
        f = self.huoqu_finding(zhiwen)
        if not f:
            raise ValueError("未找到该 Finding：" + zhiwen)

        # 硬规则：没有修复 Commit 和复扫证据，不允许置为 Verified
        if zhuangtai == "Verified":
            commit = xiufu_commit or f.get("xiufu_commit")
            pici = fusaomiao_pici or f.get("fusaomiao_pici")
            assert commit, "断言失败：缺少修复 Commit 不允许置为 Verified"
            assert pici, "断言失败：缺少复扫批次证据不允许置为 Verified"

        c = self.conn.cursor()
        c.execute(
            "UPDATE findings SET zhuangtai=? WHERE zhiwen=?",
            (zhuangtai, zhiwen),
        )
        self.conn.commit()

    def shezhi_fuzeren(self, zhiwen, fuzeren):
        """指派负责人。"""
        if not fuzeren or not fuzeren.strip():
            raise ValueError("负责人不能为空")
        c = self.conn.cursor()
        c.execute(
            "UPDATE findings SET fuzeren=? WHERE zhiwen=?",
            (fuzeren.strip(), zhiwen),
        )
        self.conn.commit()

    def shezhi_chuzhi(self, zhiwen, liyou, xiufu_fenzhi=None, xiufu_commit=None):
        """填写处置理由（误报/风险接受时必须），并可附带修复分支与 Commit。"""
        if not liyou or not liyou.strip():
            raise ValueError("处置理由不能为空")
        c = self.conn.cursor()
        sql = "UPDATE findings SET chuzhi_liyou=?"
        args = [liyou.strip()]
        if xiufu_fenzhi is not None:
            sql += ", xiufu_fenzhi=?"
            args.append(xiufu_fenzhi)
        if xiufu_commit is not None:
            sql += ", xiufu_commit=?"
            args.append(xiufu_commit)
        sql += " WHERE zhiwen=?"
        args.append(zhiwen)
        c.execute(sql, args)
        self.conn.commit()

    def guanlian_fusaomiao(self, zhiwen, pici_id):
        """把某条 Finding 与一次复扫批次关联（复扫后该指纹消失才调用）。"""
        c = self.conn.cursor()
        c.execute(
            "UPDATE findings SET fusaomiao_pici=? WHERE zhiwen=?",
            (pici_id, zhiwen),
        )
        self.conn.commit()

    def guanbi(self):
        self.conn.close()
