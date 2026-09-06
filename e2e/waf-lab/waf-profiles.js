// e2e/waf-lab/waf-profiles.js
// WAF 配置文件：3 个真实 WAF 模拟场景

// ── Profile 1: ModSecurity CRS ──
// 模拟 OWASP ModSecurity Core Rule Set 的 SQL 注入规则
export const MODSECURITY_CRS = {
  id: 'modsecurity_crs',
  name: 'ModSecurity CRS (OWASP)',
  desc: '模拟 OWASP ModSecurity Core Rule Set 942100-942360 SQL 注入规则',
  rules: [
    // 942100: SQL 注入 - 关键字匹配
    { id: 'crs_942100', re: /union\s+select/i, severity: 'CRITICAL' },
    { id: 'crs_942110', re: /union\s+all\s+select/i, severity: 'CRITICAL' },
    { id: 'crs_942120', re: /or\s+\d+\s*=\s*\d+/i, severity: 'CRITICAL' },
    { id: 'crs_942130', re: /and\s+\d+\s*=\s*\d+/i, severity: 'CRITICAL' },
    { id: 'crs_942140', re: /sleep\s*\(/i, severity: 'HIGH' },
    { id: 'crs_942150', re: /benchmark\s*\(/i, severity: 'HIGH' },
    // [拟真修正] 真实 CRS 对报错型函数（extractvalue/updatexml）有专项规则；
    // 此前缺失导致未 tamper 的报错 payload 也能穿过 WAF，waf-e2e 的 A/B 判据失真。
    // 注意 `\s*\(` 锚定：charencode 双重编码后 WAF 视角为 `extractvalue%281`，不命中 → 可被绕过（符合预期）。
    { id: 'crs_942141', re: /extractvalue\s*\(/i, severity: 'CRITICAL' },
    { id: 'crs_942142', re: /updatexml\s*\(/i, severity: 'CRITICAL' },
    { id: 'crs_942160', re: /0x[0-9a-f]{8,}/i, severity: 'HIGH' },
    { id: 'crs_942170', re: /char\s*\(\d+/i, severity: 'HIGH' },
    { id: 'crs_942180', re: /information_schema/i, severity: 'HIGH' },
    { id: 'crs_942190', re: /--\s*$/m, severity: 'MEDIUM' },
    { id: 'crs_942200', re: /#/, severity: 'MEDIUM' },
    { id: 'crs_942210', re: /into\s+(outfile|dumpfile)/i, severity: 'CRITICAL' },
    { id: 'crs_942220', re: /load_file\s*\(/i, severity: 'CRITICAL' },
    { id: 'crs_942230', re: /pg_sleep\s*\(/i, severity: 'HIGH' },
    { id: 'crs_942240', re: /waitfor\s+delay/i, severity: 'HIGH' },
    { id: 'crs_942250', re: /;\s*select/i, severity: 'MEDIUM' },  // 堆叠查询
  ],
};

// ── Profile 2: Cloudflare WAF (simulated) ──
// 模拟 Cloudflare WAF 托管规则集（SQL 注入防护）
export const CLOUDFLARE_WAF = {
  id: 'cloudflare_waf',
  name: 'Cloudflare WAF (simulated)',
  desc: '模拟 Cloudflare WAF 托管规则中 SQL 注入检测',
  rules: [
    // 关键字规则
    { id: 'cf_sqli_union', re: /union\s+select/i, severity: 'CRITICAL' },
    { id: 'cf_sqli_or', re: /or\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i, severity: 'HIGH' },
    { id: 'cf_sqli_and', re: /and\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i, severity: 'HIGH' },
    { id: 'cf_sqli_comment', re: /\/\*.*\*\//, severity: 'MEDIUM' },  // Cloudflare 拦截内联注释
    { id: 'cf_sqli_dash', re: /--\s/i, severity: 'MEDIUM' },
    { id: 'cf_sqli_hex', re: /0x[0-9a-f]{4,}/i, severity: 'MEDIUM' },
    { id: 'cf_sqli_exec', re: /exec\s*\(/i, severity: 'CRITICAL' },
    { id: 'cf_sqli_xp_cmdshell', re: /xp_cmdshell/i, severity: 'CRITICAL' },
    { id: 'cf_sqli_into_outfile', re: /into\s+outfile/i, severity: 'CRITICAL' },
    { id: 'cf_sqli_sleep', re: /sleep\s*\(\s*\d+/i, severity: 'HIGH' },
    // 请求速率/异常检测
    { id: 'cf_sqli_multi', re: /(?:union|select|or|and).*(?:union|select|or|and)/i, severity: 'MEDIUM' },
  ],
};

// ── Profile 3: All-in-one (最严格) ──
// 综合前两个 profile + 额外规则，最严格模式
export const ALL_IN_ONE = {
  id: 'all_in_one',
  name: 'All-in-One (最严格)',
  desc: '综合所有规则，最严格 WAF 模式',
  rules: [
    ...MODSECURITY_CRS.rules,
    ...CLOUDFLARE_WAF.rules.filter(r => !MODSECURITY_CRS.rules.some(mr => mr.id === r.id)),
    // 额外规则
    { id: 'aio_quote', re: /'[^']{4,}'/, severity: 'LOW' },  // 超过4字符的引号字符串
    { id: 'aio_equals', re: /\d+\s*=\s*\d+/, severity: 'LOW' },
    { id: 'aio_concat', re: /concat\s*\(/i, severity: 'MEDIUM' },
    { id: 'aio_group_concat', re: /group_concat\s*\(/i, severity: 'MEDIUM' },
    { id: 'aio_substring', re: /substring\s*\(/i, severity: 'LOW' },
    { id: 'aio_mid', re: /\bmid\s*\(/i, severity: 'LOW' },
  ],
};

export const PROFILES = [MODSECURITY_CRS, CLOUDFLARE_WAF, ALL_IN_ONE];