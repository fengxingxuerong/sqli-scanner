// ============================================================================
// requestTransform.js —— 出站请求变换扩展点（实战 P0-1，批次 D32）
//
// 解决什么问题：真实业务接口里有一大类「扫描器根本发不出合法请求」的目标：
//   ① 带签名参数的接口（`sign=md5(sorted(params)+key)`、`X-Sign`、`x-tumid` 之类）；
//   ② 整参加密的接口（请求体 AES/自定义编码，服务端解密后才拼 SQL）；
//   ③ 时间戳+nonce 防重放（超窗即拒）。
// 这些目标上，引擎把 payload 拼进 `id` 之后，`sign` 就对不上了 ⇒ 目标回 400/「签名错误」
// ⇒ 检测层看到的是「没有差异」⇒ 报告写「未检出」。这是**静默假阴性**：与「这个站没有注入」
// 长得一模一样，而实际上一次注入都没抵达业务逻辑。
//
// 本模块提供的能力：用户给一个本地模块，导出 `transform(req) -> req`，
// 在**扫描/检测阶段每条出站请求的最后一环**（即 per-scan 客户端视图上）重算签名 / 重新加密。
// 覆盖范围含保活页、CSRF 取页、登录提交这些非注入请求；
// ⚠ **不含**注入点发现阶段的爬虫/表单收集请求 —— 那一路用的是 ScanManager 构造时持有的
//   模块级单例客户端（不带 scanId），见 TODO「D32 剩下的账」第 6 条。写文档/报告时不许说成"全部"。
// 不传即零行为变化（applyScanTransform 未登记时原样返回入参对象，连拷贝都不做）。
//
// 四条硬约束（缺一不可，都是这个扩展点自身的安全与诚实边界）：
//
//  1. **变换在 SSRF/scope 校验之前、由 HttpClient 出口层之内完成**（接线见
//     `engine/scan/scanClient.js`）⇒ 校验作用于**变换之后**的 URL。
//     若反过来（先校验再变换），脚本就能把已授权的请求改写到内网元数据地址，
//     这个扩展点会立刻变成 SSRF 跳板。
//
//  2. **脚本失败一律 fail-closed：请求不发，错误上抛。**
//     绝不「签名算不出来就把原始请求发出去」—— 那等于用一次必然被目标拒绝的请求
//     去填「已检测」的账，正是本条要消灭的那类假阴性。
//
//  3. **只允许替换 url/method/headers/data/params 五个字段**（TRANSFORMABLE_KEYS）。
//     `scanId / rateGroup / signal / retry / timeoutMs / cookieJar` 是引擎的控制权：
//     交给脚本意味着一句 `return {...req, signal: undefined}` 就能摘掉取消与限速，
//     而这些能力全部是合规闸门（暂停/停止/总速率上限）。
//
//  4. **传给脚本的是副本，不回写调用方 opts。**
//     HttpClient 的重试/认证重放会**重复使用同一个 opts 对象**（见 httpClient.request 的
//     attempt 循环）⇒ 原地改一次就变成「给已签名的请求再签一次」，第二次起签名恒错。
//
// 与入口的关系：CLI 与 REST **同一道闸** —— 脚本必须放在环境变量 REQUEST_SCRIPT_DIR
// 指定的白名单目录里（见 assertScriptPath 的理由：这是出口层的代码注入面，
// 按「谁调用的」分别放行迟早漏一处）。未设置该变量时一律拒绝加载。
// ============================================================================
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { AppError, ErrorCode } from './errors.js';
import { logger } from './logger.js';
import { looksLikeInjection } from './scanValidityGuard.js';

/** 允许的脚本后缀（与 --tamper 的用户插件同一约定） */
const SCRIPT_EXT_RE = /\.(?:m|c)?js$/i;

/** 脚本可替换的字段白名单（见文件头约束 3） */
export const TRANSFORMABLE_KEYS = Object.freeze(['url', 'method', 'headers', 'data', 'params']);

/** scanId -> { fn, source, sha256, observer } */
const registry = new Map();

/**
 * 脚本路径合法性校验：后缀 + 存在 + 普通文件 + **必须落在 REQUEST_SCRIPT_DIR 之内**。
 *
 * 为什么 CLI 也要这道闸（与既有 `--tamper <file>.js` 不同）：
 *   tamper 插件只改写 payload 字符串；本脚本改写的是**整条出站请求**（URL/报文），
 *   并且运行在持有客户凭据、授权范围与出口策略的那一层 —— 它是出口层的代码注入面，
 *   而同一个引擎既跑在操作者终端也跑在长驻 HTTP 服务里。用一个显式目录把「能加载什么」
 *   钉死，比在每个入口各写一遍「这是 API 还是 CLI」的判据可靠得多（后者漏一处就全废）。
 * @param {string} rawPath 用户给的路径
 * @param {{allowedDir?: string}} [opts] 覆盖白名单根（单测用）；缺省读 REQUEST_SCRIPT_DIR
 * @returns {{resolved: string, allowedDir: string}} 已 realpath 的绝对路径
 * @throws {AppError} REQUEST_SCRIPT_INVALID
 */
export function assertScriptPath(rawPath, { allowedDir } = {}) {
  const root = String(allowedDir ?? process.env.REQUEST_SCRIPT_DIR ?? '').trim();
  if (!root) {
    throw new AppError(
      ErrorCode.REQUEST_SCRIPT_INVALID,
      '未设置 REQUEST_SCRIPT_DIR（请求变换脚本的白名单根目录），拒绝加载任何脚本。' +
      '这是出口层的代码注入面（脚本可改写 URL 与报文），必须先划一个只放可信脚本的目录：' +
      'REQUEST_SCRIPT_DIR=D:\\work\\signers',
    );
  }
  if (!existsSync(root)) {
    throw new AppError(ErrorCode.REQUEST_SCRIPT_INVALID, `REQUEST_SCRIPT_DIR 指向的目录不存在：${root}`);
  }
  let rootReal;
  try {
    rootReal = realpathSync(root);
  } catch (e) {
    throw new AppError(ErrorCode.REQUEST_SCRIPT_INVALID, `REQUEST_SCRIPT_DIR 无法解析：${root}（${e.message}）`);
  }
  if (!statSync(rootReal).isDirectory()) {
    throw new AppError(ErrorCode.REQUEST_SCRIPT_INVALID, `REQUEST_SCRIPT_DIR 必须是目录：${rootReal}`);
  }

  const p = String(rawPath ?? '').trim();
  if (!p) throw new AppError(ErrorCode.REQUEST_SCRIPT_INVALID, '请求变换脚本路径为空');
  if (!SCRIPT_EXT_RE.test(p)) {
    throw new AppError(
      ErrorCode.REQUEST_SCRIPT_INVALID,
      `请求变换脚本必须是 .js/.mjs/.cjs 文件，收到：${p}`,
    );
  }
  if (!existsSync(p)) {
    // 只报「在白名单根下没找到」，不回显候选路径之外的信息：路径探测本身是信息泄漏面
    throw new AppError(ErrorCode.REQUEST_SCRIPT_INVALID, `请求变换脚本不存在：${p}`);
  }
  let resolved;
  try {
    resolved = realpathSync(p);
  } catch (e) {
    throw new AppError(ErrorCode.REQUEST_SCRIPT_INVALID, `请求变换脚本路径无法解析：${p}（${e.message}）`);
  }
  const st = statSync(resolved);
  if (!st.isFile()) {
    throw new AppError(ErrorCode.REQUEST_SCRIPT_INVALID, `请求变换脚本不是普通文件：${resolved}`);
  }
  const rel = path.relative(rootReal, resolved);
  const inside = rel === '' || (!!rel && !rel.startsWith('..') && !path.isAbsolute(rel));
  if (!inside) {
    throw new AppError(
      ErrorCode.REQUEST_SCRIPT_INVALID,
      `请求变换脚本不在 REQUEST_SCRIPT_DIR（${rootReal}）之内：${resolved}`,
    );
  }
  return { resolved, allowedDir: rootReal };
}

/**
 * 加载并校验脚本模块（CLI / REST / 引擎入口共用）。
 * 失败一律抛 AppError(REQUEST_SCRIPT_INVALID) —— 不降级为「忽略脚本继续扫」：
 * 静默继续会让使用者以为自定义签名生效了，比报错危险得多（同 customPayloads 的硬失败口径）。
 * @param {string} rawPath
 * @param {{allowedDir?: string}} [opts]
 * @returns {Promise<{fn: Function, source: string, sha256: string}>}
 */
export async function loadRequestScript(rawPath, opts = {}) {
  const { resolved } = assertScriptPath(rawPath, opts);
  let mod;
  try {
    mod = await import(pathToFileURL(resolved).href);
  } catch (e) {
    throw new AppError(
      ErrorCode.REQUEST_SCRIPT_INVALID,
      `请求变换脚本加载失败：${resolved}（${e && e.message ? e.message : e}）`,
    );
  }
  const candidates = [mod.transform, mod.default, mod.default && mod.default.transform];
  const fn = candidates.find((f) => typeof f === 'function');
  if (!fn) {
    throw new AppError(
      ErrorCode.REQUEST_SCRIPT_INVALID,
      `请求变换脚本必须导出 transform 函数（export function transform(req){...} 或 export default fn）：${resolved}`,
    );
  }
  const sha256 = createHash('sha256').update(readFileSync(resolved)).digest('hex');
  return { fn, source: resolved, sha256 };
}

/**
 * 登记一次扫描的变换脚本（scanId 维度：批量模式下每个目标可以是不同的签名算法）。
 * @param {string} scanId
 * @param {{fn: Function, source: string, sha256: string}} entry
 */
export function registerScanTransform(scanId, entry) {
  if (!scanId || !entry || typeof entry.fn !== 'function') return;
  registry.set(scanId, { ...entry });
}

/** @param {string} scanId */
export function getScanTransform(scanId) {
  return scanId ? registry.get(scanId) || null : null;
}

/** @param {string} scanId */
export function releaseScanTransform(scanId) {
  registry.delete(scanId);
}

/** 当前登记的变换脚本数（供测试/自检确认回收生效） */
export function scanTransformCount() {
  return registry.size;
}

/**
 * 挂/摘「变换后结果」的观察者（scanRunner 用它在变换层与可信度守卫之间回传判定素材）。
 * 为什么需要这条通道：脚本一旦加密整包，`looksLikeInjection(req)` 在密文上恒为 false，
 * 守卫就分不出「基线请求」与「注入请求」——而 (a) 基线被拒 与 (b) 注入被拒 是两种不同的
 * 处置文案。只有变换层自己在加密**之前**还看得见明文 payload，故由它打标后回传。
 * @param {string} scanId
 * @param {((ev: {injected: boolean, res?: any, error?: any}) => void)|null} observer
 */
export function setTransformObserver(scanId, observer) {
  const entry = registry.get(scanId);
  if (!entry) return false;
  entry.observer = typeof observer === 'function' ? observer : null;
  return true;
}

/**
 * 扫描启动时的接线入口：config.requestScript 有值才加载并登记；未配置返回 null（零开销）。
 * @param {string} scanId
 * @param {object} config 已清洗的扫描配置
 * @param {{allowedDir?: string}} [opts] 白名单根覆盖（单测用）
 * @returns {Promise<{source: string, file: string, sha256: string}|null>}
 *          file 是 basename —— 报告里只嵌文件名与哈希，不嵌操作者的绝对路径
 */
export async function ensureScanTransform(scanId, config, opts = {}) {
  const raw = config && config.requestScript;
  if (typeof raw !== 'string' || !raw.trim()) return null;
  const entry = await loadRequestScript(raw, opts);
  registerScanTransform(scanId, entry);
  logger.warn(
    `[requestTransform] 扫描 ${scanId} 启用自定义请求变换：${entry.source}（sha256=${entry.sha256.slice(0, 16)}…）`,
  );
  return { source: entry.source, file: path.basename(entry.source), sha256: entry.sha256 };
}

/** 该扫描是否启用了变换（热路径上的短路判据） */
export function transformActiveForScan(scanId) {
  return scanId ? registry.has(scanId) : false;
}

/**
 * 对一条即将出站的请求施加变换。
 * @param {string} scanId
 * @param {object} opts HttpClient 请求参数（**不会被修改**）
 * @returns {Promise<{opts: object, injected: boolean}>} opts 原样返回（未登记时）或新对象
 * @throws {AppError} REQUEST_SCRIPT_FAILED —— 脚本抛错或产出非法请求；此时调用方必须**不发**
 */
export async function applyScanTransform(scanId, opts) {
  const entry = registry.get(scanId);
  if (!entry) return { opts, injected: false };
  // 在加密/签名之前判定「这条是不是注入请求」，供守卫区分基线与注入
  const injected = looksLikeInjection(opts);
  const view = {
    url: opts.url,
    method: opts.method,
    headers: { ...(opts.headers || {}) },
    data: opts.data,
    params: opts.params === undefined ? undefined : { ...(opts.params || {}) },
    scanId,
  };
  let out;
  try {
    out = await entry.fn(view);
  } catch (e) {
    throw new AppError(
      ErrorCode.REQUEST_SCRIPT_FAILED,
      `请求变换脚本执行异常，请求未发出：${e && e.message ? e.message : e}`,
    );
  }
  if (!out || typeof out !== 'object' || Array.isArray(out)) {
    throw new AppError(
      ErrorCode.REQUEST_SCRIPT_FAILED,
      `请求变换脚本必须返回请求对象，收到 ${out === null ? 'null' : typeof out}，请求未发出`,
    );
  }
  if (out.url !== undefined && (typeof out.url !== 'string' || !out.url)) {
    throw new AppError(
      ErrorCode.REQUEST_SCRIPT_FAILED,
      '请求变换脚本返回的 url 必须是非空字符串，请求未发出',
    );
  }
  if (out.headers !== undefined && (typeof out.headers !== 'object' || out.headers === null || Array.isArray(out.headers))) {
    throw new AppError(
      ErrorCode.REQUEST_SCRIPT_FAILED,
      '请求变换脚本返回的 headers 必须是对象，请求未发出',
    );
  }
  const patch = {};
  for (const k of TRANSFORMABLE_KEYS) {
    if (out[k] !== undefined) patch[k] = out[k];
  }
  return { opts: { ...opts, ...patch }, injected };
}

/**
 * 把「变换后请求的结果」回传给观察者（仅用于签名被拒显形，不影响请求本身）。
 * 观察者故障不得影响检测主流程 ⇒ 本函数吞掉一切异常。
 */
export function notifyTransformOutcome(scanId, ev) {
  const entry = registry.get(scanId);
  if (!entry || typeof entry.observer !== 'function') return;
  try {
    entry.observer(ev || {});
  } catch {
    /* 观察者故障不得影响发包 */
  }
}

export default { loadRequestScript, ensureScanTransform, applyScanTransform };
