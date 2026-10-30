// ============================================================================
// auditChecks.js —— 跨 DBMS 只读安全配置审计的**检查项真源**（D181）
//
// 对标 sqlmap `--audit`（2026-10-19 新增）：连上库以后，除了「能不能注入」，
// 再看一眼「这个库自身的配置有多松」。本仓的定位是交付型测试，所以这层必须满足三条：
//
//   1. **只读**：只跑 SELECT / SHOW / PRAGMA，绝不写库、不改配置、不调过程；
//   2. **不猜**：查不到（权限不足、版本不支持、字段不存在）一律标 `unknown` 并带原因，
//      绝不把「没查到」写成「通过」——这是本仓最反对的失败形态；
//   3. **可复现**：每条检查把实际执行的 SQL 与原始结果写进证据，第三方可照着重跑。
//
// 数据驱动：每个方言一张表，检查项只声明 SQL + 判定器，跑法由 audit.js 统一负责。
// ============================================================================

/**
 * @typedef {object} AuditCheck
 * @property {string} id 检查项 id（kebab，报告与 audit.json 的稳定键）
 * @property {string} title 人读标题
 * @property {'info'|'low'|'medium'|'high'} severity 命中时的风险档
 * @property {string} sql 只读 SQL（单语句）
 * @property {(row: Record<string, unknown>|undefined) => {status: 'pass'|'fail', detail: string}} judge
 *   判定器：`pass` = 配置良好，`fail` = 存在风险（`detail` 必须写清依据）
 */

/** 取第一行的第一个值（标量查询统一取值口径） */
function firstValue(row) {
  if (!row) return undefined;
  const keys = Object.keys(row);
  return keys.length ? row[keys[0]] : undefined;
}

/** 把任意值归一成小写字符串（PG 布尔可能是 true/'t'/'on'） */
function lower(v) {
  return String(v == null ? '' : v).trim().toLowerCase();
}

/** 布尔语义判定：PG 的 `t/f`、MySQL 的 `1/0`、文本 `on/off` 都认 */
function truthy(v) {
  const s = lower(v);
  return s === 't' || s === 'true' || s === '1' || s === 'on' || s === 'yes';
}

/** PostgreSQL（含 PGlite 真引擎） */
export const POSTGRES_CHECKS = [
  {
    id: 'pg-version',
    title: '数据库版本（是否仍在支持期内）',
    severity: 'info',
    sql: 'select version() as v',
    judge: (row) => {
      const v = String(firstValue(row) ?? '');
      return v ? { status: 'pass', detail: v.slice(0, 120) } : { status: 'fail', detail: '拿不到版本号' };
    },
  },
  {
    id: 'pg-current-user',
    title: '当前连接身份',
    severity: 'info',
    sql: 'select current_user as u',
    judge: (row) => {
      const u = String(firstValue(row) ?? '');
      return u ? { status: 'pass', detail: u } : { status: 'fail', detail: '拿不到当前用户' };
    },
  },
  {
    id: 'pg-superuser',
    title: '连接身份是否超级用户（最小权限原则）',
    severity: 'high',
    sql: "select rolsuper as s from pg_roles where rolname = current_user",
    judge: (row) => (truthy(firstValue(row))
      ? { status: 'fail', detail: '当前连接是超级用户：一次注入即等于整库接管' }
      : { status: 'pass', detail: '非超级用户' }),
  },
  {
    id: 'pg-createrole',
    title: '连接身份是否可创建角色（提权路径）',
    severity: 'medium',
    sql: 'select rolcreaterole as s from pg_roles where rolname = current_user',
    judge: (row) => (truthy(firstValue(row))
      ? { status: 'fail', detail: '可创建角色：可作为提权跳板' }
      : { status: 'pass', detail: '不可创建角色' }),
  },
  {
    id: 'pg-password-encryption',
    title: '口令加密方式（md5 已可离线爆破）',
    severity: 'medium',
    sql: 'show password_encryption',
    judge: (row) => {
      const v = lower(firstValue(row));
      if (!v) return { status: 'fail', detail: '读不到 password_encryption' };
      return v.includes('scram')
        ? { status: 'pass', detail: v }
        : { status: 'fail', detail: `${v}（建议 scram-sha-256）` };
    },
  },
  {
    id: 'pg-public-create',
    title: 'public schema 是否允许所有人建表',
    severity: 'medium',
    sql: "select has_schema_privilege('public', 'CREATE') as p",
    judge: (row) => (truthy(firstValue(row))
      ? { status: 'fail', detail: 'public 可写：任意用户可建表/放函数' }
      : { status: 'pass', detail: 'public 不可建表' }),
  },
  {
    id: 'pg-file-read',
    title: '当前身份能否读服务器文件（pg_read_file）',
    severity: 'high',
    sql: "select has_function_privilege(current_user, 'pg_read_file(text)', 'EXECUTE') as p",
    judge: (row) => (truthy(firstValue(row))
      ? { status: 'fail', detail: '可执行 pg_read_file：注入即可读服务器文件' }
      : { status: 'pass', detail: '不可读服务器文件' }),
  },
];

/** SQLite（sql.js / 原生） */
export const SQLITE_CHECKS = [
  {
    id: 'sqlite-version',
    title: '数据库版本',
    severity: 'info',
    sql: 'select sqlite_version() as v',
    judge: (row) => {
      const v = String(firstValue(row) ?? '');
      return v ? { status: 'pass', detail: v } : { status: 'fail', detail: '拿不到版本号' };
    },
  },
  {
    id: 'sqlite-foreign-keys',
    title: '外键约束是否开启',
    severity: 'low',
    sql: 'pragma foreign_keys',
    judge: (row) => (truthy(firstValue(row))
      ? { status: 'pass', detail: '已开启' }
      : { status: 'fail', detail: '未开启：约束不生效，脏数据可写入' }),
  },
  {
    id: 'sqlite-trusted-schema',
    title: 'trusted_schema（视图/触发器里的危险函数）',
    severity: 'medium',
    sql: 'pragma trusted_schema',
    judge: (row) => {
      const v = firstValue(row);
      if (v == null) return { status: 'fail', detail: '读不到该 pragma' };
      return truthy(v)
        ? { status: 'fail', detail: 'schema 内容可调用危险函数（load_extension 等）' }
        : { status: 'pass', detail: '已关闭' };
    },
  },
];

/** MySQL / MariaDB（无真机时全部落 unknown，见 docs/审计口径.md） */
const MYSQL_CHECKS = [
  {
    id: 'mysql-version',
    title: '数据库版本',
    severity: 'info',
    sql: 'select version() as v',
    judge: (row) => {
      const v = String(firstValue(row) ?? '');
      return v ? { status: 'pass', detail: v } : { status: 'fail', detail: '拿不到版本号' };
    },
  },
  {
    id: 'mysql-current-user',
    title: '当前连接身份',
    severity: 'info',
    sql: 'select current_user() as u',
    judge: (row) => {
      const u = String(firstValue(row) ?? '');
      return u ? { status: 'pass', detail: u } : { status: 'fail', detail: '拿不到当前用户' };
    },
  },
  {
    id: 'mysql-file-priv',
    title: '当前身份是否具备 FILE 权限（读服务器文件）',
    severity: 'high',
    sql: "select privilege_type as p from information_schema.user_privileges where privilege_type = 'FILE' limit 1",
    judge: (row) => (firstValue(row)
      ? { status: 'fail', detail: '具备 FILE 权限：可读写服务器文件' }
      : { status: 'pass', detail: '未授予 FILE 权限' }),
  },
];

/** SQL Server（LocalDB 16.0 真机已验证，D186；mssql 包直连） */
const MSSQL_CHECKS = [
  {
    id: 'mssql-version',
    title: '数据库版本',
    severity: 'info',
    sql: 'select @@version as v',
    /**
     * @param {string[]} row 查询结果首行（列值已归一化为字符串）
     * @returns {{status: 'pass'|'fail'|'unknown', detail: string}}
     */
    judge: (row) => {
      const v = String(firstValue(row) ?? '');
      return v ? { status: 'pass', detail: v } : { status: 'fail', detail: '拿不到版本号' };
    },
  },
  {
    id: 'mssql-current-user',
    title: '当前连接身份',
    severity: 'info',
    sql: 'select suser_sname() as u',
    /**
     * @param {string[]} row
     * @returns {{status: 'pass'|'fail'|'unknown', detail: string}}
     */
    judge: (row) => {
      const u = String(firstValue(row) ?? '');
      return u ? { status: 'pass', detail: u } : { status: 'fail', detail: '拿不到当前用户' };
    },
  },
  {
    id: 'mssql-sysadmin',
    title: '当前身份是否属于 sysadmin 固定服务器角色（一次注入即等于整实例接管）',
    severity: 'high',
    sql: "select case when is_srvrolemember('sysadmin') = 1 then 'yes' else 'no' end as sysadmin",
    /**
     * @param {string[]} row
     * @returns {{status: 'pass'|'fail'|'unknown', detail: string}}
     */
    judge: (row) => (String(firstValue(row) ?? '') === 'yes'
      ? { status: 'fail', detail: '属于 sysadmin：注入即可全实例接管（含 xp_cmdshell 提权路径）' }
      : { status: 'pass', detail: '不属于 sysadmin' }),
  },
];

/** Oracle（26ai Free 真机已验证，D187；oracledb thin 直连） */
const ORACLE_CHECKS = [
  {
    id: 'oracle-version',
    title: '数据库版本',
    severity: 'info',
    sql: 'select banner as v from v$version where rownum = 1',
    /**
     * @param {Record<string, unknown>|undefined} row 查询结果首行
     * @returns {{status: 'pass'|'fail', detail: string}}
     */
    judge: (row) => {
      const v = String(firstValue(row) ?? '');
      return v ? { status: 'pass', detail: v.slice(0, 120) } : { status: 'fail', detail: '拿不到版本号' };
    },
  },
  {
    id: 'oracle-current-user',
    title: '当前连接身份',
    severity: 'info',
    sql: 'select user as u from dual',
    /**
     * @param {Record<string, unknown>|undefined} row
     * @returns {{status: 'pass'|'fail', detail: string}}
     */
    judge: (row) => {
      const u = String(firstValue(row) ?? '');
      return u ? { status: 'pass', detail: u } : { status: 'fail', detail: '拿不到当前用户' };
    },
  },
  {
    id: 'oracle-sysdba',
    title: '连接身份是否具备 SYSDBA/SYSOPER 特权（一次注入即等于整实例接管）',
    severity: 'high',
    sql: "select sys_context('USERENV','ISDBA') as isdba from dual",
    /**
     * @param {Record<string, unknown>|undefined} row
     * @returns {{status: 'pass'|'fail', detail: string}}
     */
    judge: (row) => (truthy(firstValue(row))
      ? { status: 'fail', detail: '以 DBA 特权身份连接（ISDBA=TRUE）：注入即可读写任意表/调 DBMS_ 包' }
      : { status: 'pass', detail: '非 DBA 特权身份' }),
  },
  {
    id: 'oracle-dba-role',
    title: '当前身份是否被授予 DBA 角色（提权路径）',
    severity: 'medium',
    sql: "select 'yes' as d from user_role_privs where granted_role = 'DBA'",
    /**
     * @param {Record<string, unknown>|undefined} row
     * @returns {{status: 'pass'|'fail', detail: string}}
     */
    judge: (row) => (String(firstValue(row) ?? '') === 'yes'
      ? { status: 'fail', detail: '具备 DBA 角色：可管理全部 schema 与账号，可作为提权跳板' }
      : { status: 'pass', detail: '未授予 DBA 角色' }),
  },
  {
    id: 'oracle-password-verify',
    title: '默认 profile 是否启用口令复杂度校验函数',
    severity: 'medium',
    sql: 'select "LIMIT" as v from dba_profiles where profile = \'DEFAULT\' and resource_name = \'PASSWORD_VERIFY_FUNCTION\'',
    /**
     * @param {Record<string, unknown>|undefined} row
     * @returns {{status: 'pass'|'fail', detail: string}}
     */
    judge: (row) => {
      const v = lower(firstValue(row));
      if (!v) return { status: 'fail', detail: '读不到默认 profile 的口令校验函数配置' };
      if (v === 'null' || v === 'none') {
        return { status: 'fail', detail: '默认 profile 未启用口令复杂度校验函数（弱口令可直接登录）' };
      }
      return { status: 'pass', detail: v };
    },
  },
  {
    id: 'oracle-directory-priv',
    title: '当前身份能否创建目录对象（UTL_FILE 读写服务器文件）',
    severity: 'high',
    sql: "select privilege as p from user_sys_privs where privilege = 'CREATE ANY DIRECTORY'",
    /**
     * @param {Record<string, unknown>|undefined} row
     * @returns {{status: 'pass'|'fail', detail: string}}
     */
    judge: (row) => (firstValue(row)
      ? { status: 'fail', detail: '具备 CREATE ANY DIRECTORY：可把目录对象指向任意路径，配合 UTL_FILE 读写服务器文件' }
      : { status: 'pass', detail: '不可创建目录对象' }),
  },
];

/** IBM Db2（ibm_db 直连；[D189] 查询与判据以容器真机实跑校准，低权不可见的走 unknown） */
const DB2_CHECKS = [
  {
    id: 'db2-version',
    title: '数据库版本',
    severity: 'info',
    sql: 'select service_level as v from sysibmadm.env_inst_info',
    /**
     * @param {Record<string, unknown>|undefined} row 查询结果首行
     * @returns {{status: 'pass'|'fail', detail: string}}
     */
    judge: (row) => {
      const v = String(firstValue(row) ?? '');
      return v ? { status: 'pass', detail: v.slice(0, 120) } : { status: 'fail', detail: '拿不到版本号' };
    },
  },
  {
    id: 'db2-current-user',
    title: '当前连接身份',
    severity: 'info',
    sql: 'select session_user as u from sysibm.sysdummy1',
    /**
     * @param {Record<string, unknown>|undefined} row
     * @returns {{status: 'pass'|'fail', detail: string}}
     */
    judge: (row) => {
      const u = String(firstValue(row) ?? '');
      return u ? { status: 'pass', detail: u } : { status: 'fail', detail: '拿不到当前用户' };
    },
  },
  {
    id: 'db2-instance-authority',
    title: '当前身份是否具备 SYSADM/SYSCTRL 实例级权限（一次注入即等于整实例接管）',
    severity: 'high',
    // [D189 真机校准] 实例级权限不在 syscat.dbauth（那是库级授权表），用 SYSPROC 表函数；
    // 实例属主的 SYSADM 经组授予（d_user='*'，d_group='Y'），'*'+N 不是持有
    sql: "select authority as y from table(sysproc.auth_list_authorities_for_authid(SESSION_USER, 'U')) where authority in ('SYSADM','SYSCTRL') and (d_user = 'Y' or d_group = 'Y')",
    /**
     * @param {Record<string, unknown>|undefined} row
     * @returns {{status: 'pass'|'fail', detail: string}}
     */
    judge: (row) => (firstValue(row)
      ? { status: 'fail', detail: '具备 SYSADM/SYSCTRL 实例权限：注入即可读写任意表、控制实例起停' }
      : { status: 'pass', detail: '无实例级管理权限' }),
  },
  {
    id: 'db2-dbadm-holders',
    title: 'DBADM 授权面（授予身份过多即提权风险）',
    severity: 'medium',
    sql: "select count(*) as n from syscat.dbauth where dbadmauth = 'Y' and grantee <> 'SYSADM'",
    /**
     * @param {Record<string, unknown>|undefined} row
     * @returns {{status: 'pass'|'fail', detail: string}}
     */
    judge: (row) => {
      const raw = firstValue(row);
      const n = Number(raw ?? NaN);
      if (raw == null || Number.isNaN(n)) return { status: 'fail', detail: '读不到 DBADM 授权计数' };
      return n > 2
        ? { status: 'fail', detail: `DBADM 授予 ${n} 个身份（建议收敛到最小授权集）` }
        : { status: 'pass', detail: `DBADM 授予 ${n} 个身份` };
    },
  },
];

/** 方言 → 检查项表（未收录方言返回空表，由调用方标 unknown） */
export const CHECKS_BY_DIALECT = {
  postgres: POSTGRES_CHECKS,
  sqlite: SQLITE_CHECKS,
  mysql: MYSQL_CHECKS,
  mariadb: MYSQL_CHECKS,
  mssql: MSSQL_CHECKS,
  oracle: ORACLE_CHECKS,
  db2: DB2_CHECKS,
};
