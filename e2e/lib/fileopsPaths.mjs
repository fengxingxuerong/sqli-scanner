// ============================================================================
// fileopsPaths.mjs —— [D134 2026-10-23] fileRead / fileWrite 真闭环的目录判定
//
// 为什么抽成独立模块（而不是在两个 e2e 里各写一份）：
//   两个套件都要回答同一个问题——「这次实例允许我读写哪个目录？」。此前只认
//   `MYSQL_SECURE_FILE_DIR` 这个**由沙箱注入的环境变量**，于是：
//     · 沙箱里（注入了变量）→ 真跑 PASS；
//     · 宿主实例把 secure_file_priv 指到某个目录（合法且常见）→ 脚本仍往 tmpdir 写
//       ⇒ MySQL 拒绝 ⇒ `{wrote:false, verified:false}` ⇒ 验收报 FAIL。
//   2026-10-23 实测就是这样：宿主 MariaDB 的 secure_file_priv=D:\tools\mariadb\files\，
//   而套件往 `%TEMP%\mysql-fw-lab\out` 写，被拒后记成「fileWrite 能力 FAIL」——
//   **环境路径不匹配被伪装成能力退化**（本仓已栽过一次的同形问题，见 D126）。
//
// 判据（MySQL 语义，必须按这三种取值区分，不能混成"非空即放行"）：
//   · NULL         → 彻底禁用（LOAD_FILE / INTO OUTFILE 都不行）→ 套件只能 SKIP
//   · ''           → 不限制目录（可以写任何路径）→ 用调用方的兜底目录
//   · '/some/dir/' → 只允许该目录（含子目录）→ **必须**用它，否则一定失败
//
// 优先级：显式 env/override > 实例自报的 @@secure_file_priv > 调用方兜底。
// ============================================================================

/**
 * `@@secure_file_priv` 是否表示「彻底禁用」。
 * mysql2 对 SQL NULL 返回 `null`；某些链路会把它字符串化成 `'NULL'`——两种都算禁用。
 * 注意空串是「不限制」，**不是**禁用，别用真值判断。
 * @param {unknown} sfp `SELECT @@secure_file_priv` 的结果
 * @returns {boolean} true = 禁用（套件应 SKIP）
 */
export function isSecureFilePrivDisabled(sfp) {
  if (sfp === null || sfp === undefined) return true;
  return String(sfp).trim().toUpperCase() === 'NULL';
}

/**
 * 归一化目录：统一正斜杠、去掉尾部斜杠（MySQL 在 Windows 上接受正斜杠）。
 * @param {unknown} dir 原始目录
 * @returns {string} 归一化结果（空串表示没有可用目录）
 */
export function normalizeDir(dir) {
  return String(dir ?? '')
    .trim()
    .replace(/\\/g, '/')
    .replace(/\/+$/, '');
}

/**
 * 解析本次实际可用的读写目录。
 * @param {{ envDir?: string, sfp?: unknown }} input envDir=环境/参数显式指定的目录；sfp=实例自报值
 * @returns {string} 可用目录（'' = 没有限定目录，调用方自选兜底目录）
 */
export function effectiveSecureDir({ envDir, sfp } = {}) {
  const fromEnv = normalizeDir(envDir);
  if (fromEnv) return fromEnv;
  if (isSecureFilePrivDisabled(sfp)) return '';
  return normalizeDir(sfp);
}

/**
 * 解析最终目标文件路径：给定目录前缀与文件名，拼出可写路径。
 * `dir` 为空时用 `fallbackDir`（调用方用 tmpdir() 派生，保持平台无关）。
 * @param {{ dir: string, fallbackDir: string, name: string, override?: string }} input 目录/兜底/文件名/显式覆盖
 * @returns {string} 目标路径（正斜杠）
 */
export function resolveTargetFile({ dir, fallbackDir, name, override }) {
  if (override && String(override).trim()) return normalizeDir(override) || String(override);
  const base = normalizeDir(dir) || normalizeDir(fallbackDir);
  return `${base}/${name}`;
}
