import { emptyExtractedData } from './models.js';
import { logger } from '../core/logger.js';
import { defaults } from '../config/defaults.js';
import { SYS_DBS } from './scanHelpers.js';
import * as eventBus from '../core/eventBus.js';

/**
 * 完整拖库（库→表→列→数据）
 * extractScope 存在时（CLI --dbs/--tables/--columns/--dump/--current-db/--current-user/--count）
 * 走 extractByScope 定向枚举；否则保留既有全量拖库逻辑（零回归）。
 */
export async function extractAll(sm, scanId, ctx) {
  const scope = (ctx.config && ctx.config.extractScope) || (ctx.target && ctx.target.config && ctx.target.config.extractScope);
  if (scope && scope.mode) return extractByScope(sm, scanId, ctx, scope);
  const data = emptyExtractedData();
  try {
    const allDbs = await sm.extractor.enumerateDatabases(ctx);
    // 系统库过滤（对标 sqlmap --exclude-sysdbs，默认 true）：MySQL 排除
    // mysql/information_schema/performance_schema/sys，PostgreSQL 排除 pg_catalog/pg_toast/
    // information_schema，SQL Server 排除 master/model/msdb/tempdb，Oracle 排除 SYS/SYSTEM。
    // config.excludeSysdbs 显式 false 时关闭过滤（对齐 sqlmap --exclude-sysdbs=false 语义）。
    const excludeSysdbs = ctx.target?.config?.excludeSysdbs ?? defaults.excludeSysdbs;
    const dbs =
      excludeSysdbs === false
        ? allDbs
        : allDbs.filter((d) => !SYS_DBS.has(String(d).toLowerCase()));
    data.databases = dbs;
    // 库级并发拖库（受 dumpDatabaseConcurrency 约束），单库失败不影响整体
    // UNION 提取失败时自动 fallback 到堆叠深度提取（deepDump），并统计走了 fallback 的表
    const aggregated = await sm.extractor.dumpAllDatabases(ctx, dbs, {
      fallback: (c, db, table, cols) => sm.exploiter.deepDump(c, db, table, cols),
      onFallback: (t) => {
        data.meta = data.meta || {};
        (data.meta.deepDumpTables ||= []).push(t);
      },
    });
    data.tables = aggregated.tables;
    data.columns = aggregated.columns;
    data.rows = aggregated.rows;
    // [P0 2026-09-09] 「0 行未确认」表透出：空结果 ≠ 空表（提取通路可能被 WAF/类型限制拦死）
    if (aggregated.meta?.dumpUnconfirmed?.length) {
      data.meta = data.meta || {};
      data.meta.dumpUnconfirmed = aggregated.meta.dumpUnconfirmed;
    }
    // 列类型枚举 + 进度推送（库数通常不多，保持串行遍历；类型枚举失败被吞）
    for (const db of dbs) {
      const tbls = aggregated.tables[db] || [];
      eventBus.emit(scanId, 'extraction_progress', { db, table: null, count: tbls.length });
      // [MERGED: perf] 表级并发（每表 1-N 个只读请求，受 extractConcurrency 约束；原为逐表串行 await）
      await sm._mapPool(
        tbls,
        async (table) => {
          const cols = aggregated.columns[`${db}.${table}`] || [];
          data.columns[`${db}.${table}`] = cols;
          if (sm.colTypeEnum) {
            const cacheKey = `${db}.${table}`;
            try {
              let typed = sm._colTypeCache.get(cacheKey);
              if (!typed) {
                typed = await sm.colTypeEnum.enumerate(ctx, db, table, cols);
                sm._colTypeCache.set(cacheKey, typed);
              }
              data.columns[cacheKey] = typed.map((c) => `${c.name}:${c.type}`);
            } catch {
              /* 类型枚举失败不影响主流程 */
            }
          }
          const rowsArr = aggregated.rows[`${db}.${table}`] || [];
          data.rows[`${db}.${table}`] = rowsArr;
          eventBus.emit(scanId, 'extraction_progress', {
            db,
            table,
            count: rowsArr.length,
          });
        },
        Math.max(1, Number(ctx.target?.config?.extractConcurrency) || defaults.extractConcurrency || 2)
      );
    }
  } catch (e) {
    logger.warn(`提取失败：${e.message}`);
  }
  return data;
}

/**
 * 枚举模式提取（对标 sqlmap --dbs/--tables/--columns/--dump/--current-db/--current-user/--count）。
 * extractScope = { mode, dbs?, tables?, cols?, excludeSysdbs? }
 *   dbs/tables 为数组；cols 为逗号串或数组；excludeSysdbs 默认 true。
 * 返回与 emptyExtractedData 同结构的对象（含 mode 专用字段 currentDb/currentUser/counts）。
 */
export async function extractByScope(sm, scanId, ctx, scope) {
  const data = emptyExtractedData();
  // 读取优先级：scope.excludeSysdbs > config.excludeSysdbs > defaults.excludeSysdbs（一致性修复）
  const excludeSysdbs = scope.excludeSysdbs !== undefined
    ? scope.excludeSysdbs !== false
    : (ctx.target?.config?.excludeSysdbs ?? defaults.excludeSysdbs);
  const filterDbs = (dbs) =>
    excludeSysdbs ? dbs.filter((d) => !SYS_DBS.has(String(d).toLowerCase())) : dbs;

  const ensureExtractor = (name) => {
    const fn = sm.extractor && sm.extractor[name];
    if (typeof fn !== 'function') {
      throw new Error(`Extractor 未实现 ${name}，无法执行 --${scope.mode} 枚举`);
    }
    return fn.bind(sm.extractor);
  };

  try {
    switch (scope.mode) {
      case 'dbs': {
        const dbs = await sm.extractor.enumerateDatabases(ctx);
        data.databases = filterDbs(dbs);
        break;
      }
      case 'tables': {
        const wanted = (scope.dbs && scope.dbs.length)
          ? scope.dbs
          : filterDbs(await sm.extractor.enumerateDatabases(ctx));
        for (const db of wanted) {
          try {
            const tbls = await sm.extractor.enumerateTables(ctx, db);
            data.tables[db] = tbls;
          } catch (e) {
            logger.warn(`枚举表失败 db=${db}：${e.message}`);
            data.tables[db] = [];
          }
        }
        break;
      }
      case 'columns': {
        const wanted = (scope.dbs && scope.dbs.length)
          ? scope.dbs
          : filterDbs(await sm.extractor.enumerateDatabases(ctx));
        for (const db of wanted) {
          const tbls = (scope.tables && scope.tables.length)
            ? scope.tables
            : (data.tables[db] = await sm.extractor.enumerateTables(ctx, db));
          if (!scope.tables || !scope.tables.length) data.tables[db] = tbls;
          for (const t of tbls) {
            try {
              data.columns[`${db}.${t}`] = await sm.extractor.enumerateColumns(ctx, db, t);
            } catch (e) {
              logger.warn(`枚举列失败 ${db}.${t}：${e.message}`);
              data.columns[`${db}.${t}`] = [];
            }
          }
        }
        break;
      }
      // [对标 sqlmap --dump-all] 全库拖库：枚举全部库 → dumpAllDatabases 统一并发治理
      // （复用既有 unconfirmedEmpty 通道：0 行且未确认的表必须在报告里可见，不能当空表）
      case 'dumpAll': {
        const dbs = filterDbs(await sm.extractor.enumerateDatabases(ctx));
        if (!dbs.length) {
          logger.warn('全库拖库：未枚举到任何数据库（可能是权限不足或 information_schema 被拦）');
          break;
        }
        const dumped = await sm.extractor.dumpAllDatabases(ctx, dbs, {
          // [对标 sqlmap --where] 全库拖库同样支持条件过滤
          where: ctx.config?.dumpWhere || null,
          onUnconfirmedEmpty: (db, t) =>
            logger.warn(`全库拖库：${db}.${t} 返回 0 行且未确认（空表 / 无权限 / 被拦截）`),
        });
        data.databases = dumped.databases;
        data.tables = dumped.tables;
        data.columns = dumped.columns;
        data.rows = dumped.rows;
        if (dumped.meta) data.meta = dumped.meta;
        break;
      }
      // [对标 sqlmap --common-tables] 字典爆破表名：information_schema 不可用时的唯一出路
      case 'commonTables': {
        const dbs = (scope.dbs && scope.dbs.length)
          ? scope.dbs
          : filterDbs(await sm.extractor.enumerateDatabases(ctx));
        if (!dbs.length) { logger.warn('common-tables：无可爆破的数据库（-D 未指定且枚举为空）'); break; }
        for (const db of dbs) {
          const found = await sm.extractor.findCommonTables(ctx, db);
          data.tables[db] = found.tables;
          if (found.tried) data.meta = { ...(data.meta || {}), commonTables: { ...((data.meta || {}).commonTables || {}), [db]: { tried: found.tried, found: found.tables.length } } };
        }
        break;
      }
      // [对标 sqlmap --common-columns] 字典爆破列名（需先有表名：-T 指定或 commonTables 结果）
      case 'commonColumns': {
        const dbs = (scope.dbs && scope.dbs.length)
          ? scope.dbs
          : filterDbs(await sm.extractor.enumerateDatabases(ctx));
        for (const db of dbs) {
          const tbls = (scope.tables && scope.tables.length)
            ? scope.tables
            : await sm.extractor.findCommonTables(ctx, db).then((r) => r.tables);
          data.tables[db] = tbls;
          for (const t of tbls) {
            const found = await sm.extractor.findCommonColumns(ctx, db, t);
            data.columns[`${db}.${t}`] = found.columns;
          }
        }
        break;
      }
      case 'dump': {
        const wanted = (scope.dbs && scope.dbs.length)
          ? scope.dbs
          : filterDbs(await sm.extractor.enumerateDatabases(ctx));
        const colsList = Array.isArray(scope.cols)
          ? scope.cols
          : (scope.cols ? String(scope.cols).split(',').map((s) => s.trim()).filter(Boolean) : null);
        for (const db of wanted) {
          const tbls = (scope.tables && scope.tables.length)
            ? scope.tables
            : (await sm.extractor.enumerateTables(ctx, db));
          data.tables[db] = tbls;
          for (const t of tbls) {
            try {
              const cols = colsList || (await sm.extractor.enumerateColumns(ctx, db, t));
              data.columns[`${db}.${t}`] = cols;
              // [对标 sqlmap --where] 条件过滤透传（条件原样进 SQL，与 sqlmap 行为一致）
              data.rows[`${db}.${t}`] = await sm.extractor.dumpData(ctx, db, t, cols, undefined, {
                where: ctx.config?.dumpWhere || null,
              });
            } catch (e) {
              logger.warn(`拖库失败 ${db}.${t}：${e.message}`);
              data.rows[`${db}.${t}`] = [];
            }
          }
        }
        break;
      }
      case 'currentDb': {
        // null 也是有效结果（SQLite 无会话库概念），无条件记录便于调用方区分"未提取"与"提取为空"
        data.currentDb = await ensureExtractor('currentDb')(ctx);
        break;
      }
      case 'currentUser': {
        data.currentUser = await ensureExtractor('currentUser')(ctx);
        break;
      }
      case 'users': {
        // 凭据收割（对标 sqlmap --users）：返回逗号分隔用户串或 null（权限不足静默降级）
        data.users = await ensureExtractor('enumerateUsers')(ctx);
        break;
      }
      case 'passwords': {
        // 凭据收割（对标 sqlmap --passwords）：返回逗号分隔 user:hash 串或 null（权限不足静默降级）
        data.passwords = await ensureExtractor('enumeratePasswords')(ctx);
        break;
      }
      case 'hostname': {
        // 主机名/地址（对标 sqlmap --hostname）；null 也是有效结果（SQLite 无概念/查询失败）
        data.hostname = await ensureExtractor('enumerateHostname')(ctx);
        break;
      }
      case 'isDba': {
        // 当前用户是否 DBA（对标 sqlmap --is-dba）：返回 '1'/'0' 或 null
        data.isDba = await ensureExtractor('enumerateIsDba')(ctx);
        break;
      }
      case 'schema': {
        // 表结构/列定义（对标 sqlmap --schema）：需要 -D <db> -T <table>
        const wanted = (scope.dbs && scope.dbs.length)
          ? scope.dbs
          : filterDbs(await sm.extractor.enumerateDatabases(ctx));
        const tbls = (scope.tables && scope.tables.length)
          ? scope.tables
          : (await sm.extractor.enumerateTables(ctx, wanted[0]));
        if (!scope.tables || !scope.tables.length) data.tables[wanted[0]] = tbls;
        for (const t of tbls) {
          try {
            for (const db of wanted) {
              const s = await ensureExtractor('enumerateSchema')(ctx, db, t);
              data.schemas[`${db}.${t}`] = s == null ? null : s;
            }
          } catch (e) {
            logger.warn(`枚举 schema 失败 ${wanted[0]}.${t}：${e.message}`);
            data.schemas[`${wanted[0]}.${t}`] = null;
          }
        }
        break;
      }
      case 'privileges': {
        // 用户权限（对标 sqlmap --privileges）：返回逗号分隔权限串或 null
        data.userPrivs = await ensureExtractor('enumerateUserPrivs')(ctx);
        break;
      }
      case 'roles': {
        // 角色（对标 sqlmap --roles）：返回逗号分隔角色串或 null
        data.roles = await ensureExtractor('enumerateRoles')(ctx);
        break;
      }
      case 'count': {
        const wanted = (scope.dbs && scope.dbs.length)
          ? scope.dbs
          : filterDbs(await sm.extractor.enumerateDatabases(ctx));
        data.counts = {};
        for (const db of wanted) {
          const tbls = (scope.tables && scope.tables.length)
            ? scope.tables
            : (await sm.extractor.enumerateTables(ctx, db));
          if (!scope.tables || !scope.tables.length) data.tables[db] = tbls;
          for (const t of tbls) {
            try {
              const n = await ensureExtractor('countRows')(ctx, db, t);
              data.counts[`${db}.${t}`] = n == null ? null : Number(n);
            } catch (e) {
              logger.warn(`行数统计失败 ${db}.${t}：${e.message}`);
              data.counts[`${db}.${t}`] = null;
            }
          }
        }
        break;
      }
      case 'search': {
        // --search <keyword>：遍历所有库的表/列名，过滤出包含 keyword 的项。
        // 实现分层（消除与 Extractor.searchTables/searchColumns 的双实现漂移）：
        //   1) 强实现：当 Extractor 提供 searchTables/searchColumns（跨全库 SQL LIKE，
        //      不受 3 库×10 表截断，支持 13+ 方言）时优先使用，覆盖全库全表；
        //   2) 朴素枚举兜底：强实现缺失（如 mock/桩）或返回空时，降级回逐库枚举，
        //      并保持原有限流语义（最多 3 库 × 每库 10 表）。
        const MAX_DBS = 3;
        const MAX_TABLES_PER_DB = 10;
        const keyword = String(scope.keyword || '').toLowerCase();
        const allDbs = filterDbs(await sm.extractor.enumerateDatabases(ctx));
        // keyword 为空时直接返回空结果
        if (!keyword) {
          data.databases = [];
          data.search = { keyword: '', matchedTables: /** @type {any[]} */ ([]), matchedColumns: /** @type {any[]} */ ([]) };
          break;
        }
        data.databases = allDbs;
        const matchedTables = [];
        const matchedColumns = [];
        const hasStrong = sm.extractor &&
          typeof sm.extractor.searchTables === 'function' &&
          typeof sm.extractor.searchColumns === 'function';
        // 表名搜索：强实现跨全库 LIKE（仅 1 次提取请求，不受库/表数截断），返回 "db.table" 数组
        let strongTableHit = false;
        if (hasStrong) {
          try {
            const st = await sm.extractor.searchTables(ctx, scope.keyword);
            if (Array.isArray(st) && st.length) {
              // 规范化：确保 "db.table" 前缀形态（SQLite 返回裸 "table"，补 main. 前缀与展示一致）
              for (const raw of st) {
                const s = String(raw);
                if (s.includes('.')) matchedTables.push(s);
                else matchedTables.push(`main.${s}`);
              }
              strongTableHit = true;
            }
          } catch (e) {
            logger.warn(`search: searchTables 失败，降级朴素枚举：${e.message}`);
          }
        }
        if (!strongTableHit) {
          // 朴素枚举兜底（保持原有限流语义与 data.tables 填充）
          for (const db of allDbs.slice(0, MAX_DBS)) {
            let tbls;
            try {
              tbls = await sm.extractor.enumerateTables(ctx, db);
            } catch (e) {
              logger.warn(`search: 枚举表失败 db=${db}：${e.message}`);
              data.tables[db] = [];
              continue;
            }
            tbls = tbls.slice(0, MAX_TABLES_PER_DB);
            data.tables[db] = tbls;
            const matchedTblsForDb = tbls.filter((t) => String(t).toLowerCase().includes(keyword));
            for (const mt of matchedTblsForDb) {
              matchedTables.push(`${db}.${mt}`);
            }
          }
        }
        // 列名搜索：强实现返回 "db.table.column" 数组（或两段 "table.column"）
        let strongColHit = false;
        if (hasStrong) {
          try {
            const sc = await sm.extractor.searchColumns(ctx, scope.keyword);
            if (Array.isArray(sc) && sc.length) {
              const byTable = new Map();
              for (const raw of sc) {
                const parts = String(raw).split('.');
                let tableKey; let colName;
                if (parts.length >= 3) {
                  tableKey = `${parts[0]}.${parts[1]}`;
                  colName = parts.slice(2).join('.');
                } else if (parts.length === 2) {
                  tableKey = parts[0];
                  colName = parts[1];
                } else {
                  continue;
                }
                if (!byTable.has(tableKey)) byTable.set(tableKey, []);
                byTable.get(tableKey).push(colName);
              }
              for (const [tableKey, cols] of byTable) {
                matchedColumns.push({ table: tableKey, columns: cols });
              }
              strongColHit = true;
            }
          } catch (e) {
            logger.warn(`search: searchColumns 失败，降级逐表枚举：${e.message}`);
          }
        }
        if (!strongColHit) {
          // 朴素枚举兜底：列匹配需逐表枚举列（限流 3 库 × 10 表），同时填充 data.tables/data.columns
          for (const db of allDbs.slice(0, MAX_DBS)) {
            let tbls = (data.tables && data.tables[db]) || [];
            if (!tbls.length) {
              try {
                tbls = await sm.extractor.enumerateTables(ctx, db);
              } catch (e) {
                logger.warn(`search: 枚举表失败 db=${db}：${e.message}`);
                data.tables[db] = [];
                continue;
              }
              tbls = tbls.slice(0, MAX_TABLES_PER_DB);
              data.tables[db] = tbls;
            }
            for (const t of tbls) {
              try {
                const cols = await sm.extractor.enumerateColumns(ctx, db, t);
                data.columns[`${db}.${t}`] = cols;
                const matchedCols = cols.filter((c) => String(c).toLowerCase().includes(keyword));
                if (matchedCols.length) {
                  matchedColumns.push({ table: `${db}.${t}`, columns: matchedCols });
                }
              } catch (e) {
                logger.warn(`search: 枚举列失败 ${db}.${t}：${e.message}`);
                data.columns[`${db}.${t}`] = [];
              }
            }
          }
        }
        data.search = { keyword: scope.keyword, matchedTables, matchedColumns };
        break;
      }
      default:
        throw new Error(`未知 extractScope.mode: ${scope.mode}`);
    }
  } catch (e) {
    logger.warn(`枚举提取失败（mode=${scope.mode}）：${e.message}`);
  }
  return data;
}

/** 合并两个提取结果数据对象（src 合并到 target） */
export function mergeExtracted(target, src) {
  if (!src) return;
  // 防御：提取返回结构残缺（如桩/部分失败）时不抛错，仅合并已有字段
  for (const db of (src.databases || [])) {
    if (!target.databases.includes(db)) target.databases.push(db);
  }
  for (const [k, v] of Object.entries(src.tables || {})) target.tables[k] = v;
  for (const [k, v] of Object.entries(src.columns || {})) target.columns[k] = v;
  for (const [k, v] of Object.entries(src.rows || {})) target.rows[k] = v;
  // 枚举模式专有字段（--current-db / --current-user / --count）
  if (src.currentDb !== undefined) target.currentDb = src.currentDb;
  if (src.currentUser !== undefined) target.currentUser = src.currentUser;
  if (src.users !== undefined) target.users = src.users;
  if (src.passwords !== undefined) target.passwords = src.passwords;
  if (src.counts) target.counts = { ...(target.counts || {}), ...src.counts };
  // 枚举模式专有字段（--hostname / --is-dba / --schema / --privileges / --roles）
  if (src.hostname !== undefined) target.hostname = src.hostname;
  if (src.isDba !== undefined) target.isDba = src.isDba;
  if (src.userPrivs !== undefined) target.userPrivs = src.userPrivs;
  if (src.roles !== undefined) target.roles = src.roles;
  if (src.schemas) target.schemas = { ...(target.schemas || {}), ...src.schemas };
  // [P0 2026-09-09] 「0 行未确认」标注透传（meta 形态：{ dumpUnconfirmed: ['db.t', …] }）
  if (src.meta?.dumpUnconfirmed?.length) {
    target.meta = target.meta || {};
    const prev = Array.isArray(target.meta.dumpUnconfirmed) ? target.meta.dumpUnconfirmed : [];
    target.meta.dumpUnconfirmed = [...new Set([...prev, ...src.meta.dumpUnconfirmed])];
  }
}

/** 检查提取结果是否包含有效数据 */
export function hasExtractedData(data) {
  return !!(
    (data.databases && data.databases.length) ||
    (data.tables && Object.keys(data.tables).length) ||
    (data.rows && Object.keys(data.rows).length) ||
    data.currentDb ||
    data.currentUser ||
    data.users ||
    data.passwords ||
    data.hostname ||
    data.isDba ||
    data.userPrivs ||
    data.roles ||
    (data.schemas && Object.keys(data.schemas).length) ||
    (data.counts && Object.values(data.counts).some((v) => v != null))
  );
}