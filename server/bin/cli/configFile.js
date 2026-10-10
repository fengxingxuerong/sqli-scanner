// ============================================================================
// configFile.js —— 配置档案（[D41 2026-10-11 对标 sqlmap -c/--save + ffuf -config]）
//
//   --config <file>      预载 JSON 参数档案（键 = 长参数名，如 {"url":…, "level":5}），
//                        CLI 显式传入的开关优先生效（argv > file > 内置默认）。
//   --save-config <file> 把本次实际生效的参数增量（相对内置默认的差异）写回 JSON，可复扫。
//
// 为什么单独一个文件 + 显式键注册表：parseArgs 的参数对象里有一批「只有传了才存在」的
// 动态键（--os-shell/--prefix/--crawl…），用 parseArgs([]) 的默认键集判「未知键」会把它们
// 全部误杀。这里集中登记两份清单：KNOWN_ARG_KEYS（合法键全集）与 INTERNAL_ARG_KEYS
// （内部字段，永不落盘）——--config 的未知键硬拒、--save-config 的增量裁剪共用同一份事实。
//
// 语义红线（与 unknownFlagError 同一条政策）：档案里写错的键宁可拒绝启动，也不静默忽略
// —— 否则「以为设了 level 5」实际没设，扫描照跑、结论照出，比报错危险得多。
// ============================================================================
import { readFileSync, writeFileSync, existsSync } from 'node:fs';

/** 内部/派生字段：不进配置档案、也不能从档案预载 */
export const INTERNAL_ARG_KEYS = new Set([
  'headerObj', // -r 请求文件解析出的 header 对象（buildAuth 消费；应写 "headers" 键）
  'unknownFlags', // 未知开关收集器（parseArgs 内部）
  'tamperResolved', // --tamper=<file.js> 异步解析结果（main 流程派生）
  'payloadEntries', // --payload-file 加载结果（main 流程派生；重扫请写 "payloadFile" 键）
  'rateGroup', // 批量模式内部生成的共享限速桶 id
  'configFile', // 本指针自身（防止档案里再嵌档案引用）
  'saveConfigFile',
]);

/**
 * 合法档案键全集 = parseArgs 默认对象键 ∪ 动态键登记表。
 * 默认键从 parseArgs([]) 现算（单一事实来源，args.js 增删键时这里自动跟随）；
 * 动态键（parseArgs 循环里才赋值的）在这里显式登记。
 * @param {(argv: string[]) => any} parseArgsFn
 */
export function buildKnownArgKeys(parseArgsFn) {
  const dyn = [
    // —— 攻击/利用 ——
    'osShell', 'udfHex', 'udfInstall', 'payloadFile',
    // —— 检测调参 ——
    'testFilter', 'testSkip', 'useRegistry', 'invalidBignum', 'invalidLogical', 'invalidString',
    'knownPoint', 'prefix', 'suffix', 'string', 'notString', 'code', 'textOnly', 'titles', 'regexp',
    'predictOutput', 'skipStatic', 'noCast', 'hex', 'unionCols', 'unionFrom',
    'flushSession', 'freshQueries', 'parseErrors', 'confirmExtreme',
    // —— 爬虫/表单/会话 ——
    'forms', 'crawl', 'sessionFile', 'timeSec', 'delay', 'delaySec', 'maxRequests', 'reqRate',
    'startRow', 'stopRow', 'safeUrl', 'safeFreq', 'proxyBypassLocal',
    // —— CSRF/认证/网络 ——
    'csrfUrl', 'csrfTokenName', 'csrfMethod', 'csrfRefreshFreq', 'skipParams',
    'tor', 'mobile', 'retries', 'httpTimeoutMs', 'refreshUrl', 'refreshToken', 'refreshField',
    'requestScript', 'clientCert', 'xmlBody', 'xmlBodyFile',
    // —— 入口控制 ——
    'advise', 'yes',
    // —— [D41] 注入点筛选三件套 / 配置档案 ——
    'testParam', 'paramExclude', 'paramFilter', 'configFile', 'saveConfigFile',
  ];
  const known = new Set(Object.keys(parseArgsFn([])));
  for (const k of dyn) known.add(k);
  // 内部/派生键从合法集剔除：档案里写它们与写未知键同罪（都该被列出，而不是被静默剔除）
  for (const k of INTERNAL_ARG_KEYS) known.delete(k);
  return known;
}

/**
 * 读取并校验 --config 档案。返回 { preset, unknown }：
 *   preset  —— 过滤掉内部键后的预载对象（交给 parseArgs 作底）
 *   unknown —— 非法键名列表（调用方硬拒；宁可拒绝启动也不静默忽略）
 * @param {string} filePath @param {Set<string>} knownKeys
 */
export function loadConfigFile(filePath, knownKeys) {
  if (!existsSync(filePath)) {
    throw new Error(`--config 文件不存在：${filePath}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(filePath, 'utf-8'));
  } catch (e) {
    throw new Error(`--config 文件不是合法 JSON：${filePath}（${e?.message || e}）`, { cause: e });
  }
  if (parsed == null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`--config 文件必须是 JSON 对象（键=长参数名，值=参数值）：${filePath}`);
  }
  const preset = {};
  const unknown = [];
  for (const [k, v] of Object.entries(parsed)) {
    if (INTERNAL_ARG_KEYS.has(k)) continue; // 内部字段：直接剔除（不报错，档案可能来自 --save-config 的旧版本）
    if (!knownKeys.has(k)) {
      unknown.push(k);
      continue;
    }
    preset[k] = v;
  }
  return { preset, unknown };
}

/**
 * 计算本次实际生效参数相对内置默认的增量（--save-config 落盘内容）。
 * 动态键（不在默认对象里）只要有值就计入；对象/数组按 JSON 序列化比较。
 * @param {any} args parseArgs 产物
 * @param {(argv: string[]) => any} parseArgsFn
 */
export function diffFromDefaults(args, parseArgsFn) {
  const base = parseArgsFn([]);
  const out = {};
  for (const [k, v] of Object.entries(args || {})) {
    if (INTERNAL_ARG_KEYS.has(k)) continue;
    if (v === undefined) continue;
    if (!(k in base)) {
      out[k] = v;
      continue;
    }
    const bv = base[k];
    const same = typeof v === 'object' && v !== null
      ? JSON.stringify(v) === JSON.stringify(bv)
      : v === bv;
    if (!same) out[k] = v;
  }
  return out;
}

/** 落盘 --save-config。返回写入的键数。 */
export function saveConfigFile(filePath, args, parseArgsFn) {
  const delta = diffFromDefaults(args, parseArgsFn);
  writeFileSync(filePath, JSON.stringify(delta, null, 2) + '\n', 'utf-8');
  return Object.keys(delta).length;
}

/**
 * 从 argv 预扫 `--config <file>` 并产出 preset（bin/cli.js 与 one-click-scan 两个入口共用）。
 * 返回 null 表示 argv 未带 --config；档案非法/含未知键直接抛错（调用方打印后以非零退出）。
 * 为什么做成共享助手：one-click 有自己的入口流程但复用同一 parseArgs —— 若只在 cli.js
 * 接预载，one-click 用户传 --config 会被静默忽略（「传了没生效」红线），两入口必须同源。
 * @param {string[]} argv @param {(argv: string[], preset?: object) => any} parseArgsFn
 */
export function presetFromArgv(argv, parseArgsFn) {
  const i = argv.indexOf('--config');
  if (i === -1 || !argv[i + 1] || argv[i + 1].startsWith('--')) return null;
  const { preset, unknown } = loadConfigFile(argv[i + 1], buildKnownArgKeys(parseArgsFn));
  if (unknown.length) {
    throw new Error(
      `--config 档案含未知键：${unknown.join(', ')}\n` +
      '  这些键不会生效，本次启动已拒绝 —— 宁可少跑一次，也不让「以为设了」变成实际没设。\n' +
      '  键名须为长参数名（去前导 --，如 level / tamper / test-param 译作 testParam）；用 --help 核对。'
    );
  }
  return preset;
}
