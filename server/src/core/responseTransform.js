// ============================================================================
// responseTransform.js —— 入站响应解密扩展点（批次 D52，--postprocess）
//
// 解决什么问题：``--request-script`` 管的是「发得出合法请求」，本模块管它的对偶面——
// 「读得懂合法响应」。真实业务里同样有一大类目标把**响应体加密**后再返回：
//   ① 整包 AES/国密加密的 JSON 信封（`{data: "<base64密文>"}`，或整个 body 就是密文）；
//   ② 响应体签名/编码包装（自定义 Base64 变体、字节序反转、压缩+加密叠加）；
//   ③ 前端框架的序列化格式（部分自研 RPC 的把返回值序列化后再塞进 HTML）。
// 这些目标上，检测层拿到的每个响应都是密文 ⇒ 真/假条件的响应差异被加密抹平
// （相同明文也可能因 IV/随机 nonce 产生不同密文，反之密文比较毫无意义）
// ⇒ 报告写「未检出」。这是与「这个站没有注入」长得一模一样的**静默假阴性**。
//
// 本模块提供的能力：用户给一个本地模块，导出 `transform(res) -> res`，
// 在 per-scan 客户端视图的**最内层**对每条响应体（`data`）做解密/解码，
// 之后检测/提取/可信度守卫看到的都是明文。与 requestTransform 同构：
// 不传即零行为变化（responseTransformActiveForScan 为 false 时连包装都不加）。
//
// 覆盖范围与边界（写文档/报告时不许含混）：
//   · 只覆盖经 getScanClient 的扫描/检测阶段请求（含保活/CSRF 取页/登录提交）；
//     **不含**注入点发现阶段的爬虫/表单收集请求（与 requestTransform 同一边界）。
//   · 只允许替换 `data`（响应体文本）。status/headers 不可改 —— status 是可信度
//     判账（拦截/会话失效/5xx）的输入，交给脚本就能把一次 403 洗成 200。
//
// 四条硬约束（与 requestTransform 逐条对偶）：
//  1. **白名单目录**：脚本必须落在环境变量 RESPONSE_SCRIPT_DIR 之内（见
//     requestTransform.assertScriptPath 的理由：这是出口/入口层的代码注入面，
//     按「谁调用的」分别放行迟早漏一处）。未设置该变量时一律拒绝加载。
//  2. **fail-closed**：脚本抛错或产出非法形态 ⇒ AppError(RESPONSE_SCRIPT_FAILED)
//     上抛，该响应按「请求失败」处理（_send 记 null，位置重试/放弃，与网络失败同义）。
//     绝不「解不动就用密文继续比」——那正是本扩展点要消灭的静默假阴性。
//  3. **只换 data**：RESPONSE_TRANSFORMABLE_KEYS = ['data']，且必须是字符串。
//  4. **传给脚本的是副本，不回写调用方响应**。响应对象会被重试/认证重放路径复用，
//     原地改写会让第二次拿到的是「解密后的密文」。
// ============================================================================
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import { AppError, ErrorCode } from './errors.js';
import { logger } from './logger.js';
import { assertScriptPath } from './requestTransform.js';

/** 脚本可替换的字段白名单（见文件头约束 3）：只有响应体文本 */
export const RESPONSE_TRANSFORMABLE_KEYS = Object.freeze(['data']);

/** scanId -> { fn, source, sha256 } */
const registry = new Map();

/**
 * 响应解密脚本路径合法性校验：后缀 + 存在 + 普通文件 + **必须落在 RESPONSE_SCRIPT_DIR 之内**。
 * 复用 requestTransform.assertScriptPath 的全部路径判据（含 realpath/目录内检查），
 * 只把白名单根换成 RESPONSE_SCRIPT_DIR、文案换成「响应解密脚本」。
 * @param {string} rawPath 用户给的路径
 * @param {{allowedDir?: string}} [opts] 覆盖白名单根（单测用）；缺省读 RESPONSE_SCRIPT_DIR
 * @returns {{resolved: string, allowedDir: string}} 已 realpath 的绝对路径
 * @throws {AppError} RESPONSE_SCRIPT_INVALID
 */
export function assertResponseScriptPath(rawPath, { allowedDir } = {}) {
  const root = String(allowedDir ?? process.env.RESPONSE_SCRIPT_DIR ?? '').trim();
  if (!root) {
    throw new AppError(
      ErrorCode.RESPONSE_SCRIPT_INVALID,
      '未设置 RESPONSE_SCRIPT_DIR（响应解密脚本的白名单根目录），拒绝加载任何脚本。' +
      '这是入口层的代码注入面（脚本可读全部响应体，含带凭据的页面），必须先划一个只放可信脚本的目录：' +
      'RESPONSE_SCRIPT_DIR=D:\\work\\decryptors',
    );
  }
  return assertScriptPath(rawPath, {
    allowedDir: root,
    envVar: 'RESPONSE_SCRIPT_DIR',
    label: '响应解密脚本',
    invalidCode: ErrorCode.RESPONSE_SCRIPT_INVALID,
  });
}

/**
 * 加载并校验脚本模块（CLI / REST / 引擎入口共用）。
 * 失败一律抛 AppError(REQUEST_SCRIPT_INVALID) —— 与 requestScript 同口径：
 * 静默忽略脚本会让使用者以为解密生效了，比报错危险得多。
 * @param {string} rawPath
 * @param {{allowedDir?: string}} [opts]
 * @returns {Promise<{fn: Function, source: string, sha256: string}>}
 */
export async function loadResponseScript(rawPath, opts = {}) {
  const { resolved } = assertResponseScriptPath(rawPath, opts);
  let mod;
  try {
    mod = await import(pathToFileURL(resolved).href);
  } catch (e) {
    throw new AppError(
      ErrorCode.RESPONSE_SCRIPT_INVALID,
      `响应解密脚本加载失败：${resolved}（${e && e.message ? e.message : e}）`,
    );
  }
  const candidates = [mod.transform, mod.default, mod.default && mod.default.transform];
  const fn = candidates.find((f) => typeof f === 'function');
  if (!fn) {
    throw new AppError(
      ErrorCode.RESPONSE_SCRIPT_INVALID,
      `响应解密脚本必须导出 transform 函数（export function transform(res){...} 或 export default fn）：${resolved}`,
    );
  }
  const sha256 = createHash('sha256').update(readFileSync(resolved)).digest('hex');
  return { fn, source: resolved, sha256 };
}

/**
 * 登记一次扫描的响应解密脚本（scanId 维度：批量模式下每个目标可以是不同加密方案）。
 * @param {string} scanId
 * @param {{fn: Function, source: string, sha256: string}} entry
 */
export function registerResponseTransform(scanId, entry) {
  if (!scanId || !entry || typeof entry.fn !== 'function') return;
  registry.set(scanId, { ...entry });
}

/** @param {string} scanId */
export function getResponseTransform(scanId) {
  return scanId ? registry.get(scanId) || null : null;
}

/** @param {string} scanId */
export function releaseResponseTransform(scanId) {
  registry.delete(scanId);
}

/** 当前登记的响应解密脚本数（供测试/自检确认回收生效） */
export function responseTransformCount() {
  return registry.size;
}

/**
 * 扫描启动时的接线入口：config.postprocess 有值才加载并登记；未配置返回 null（零开销）。
 * 硬失败口径同 ensureScanTransform：加载失败 ⇒ 扫描不启动。
 * @param {string} scanId
 * @param {object} config 已清洗的扫描配置
 * @param {{allowedDir?: string}} [opts] 白名单根覆盖（单测用）
 * @returns {Promise<{source: string, file: string, sha256: string}|null>}
 */
export async function ensureResponseTransform(scanId, config, opts = {}) {
  const raw = config && config.postprocess;
  if (typeof raw !== 'string' || !raw.trim()) return null;
  const entry = await loadResponseScript(raw, opts);
  registerResponseTransform(scanId, entry);
  logger.warn(
    `[responseTransform] 扫描 ${scanId} 启用自定义响应解密：${entry.source}（sha256=${entry.sha256.slice(0, 16)}…）`,
  );
  return { source: entry.source, file: pathBasename(entry.source), sha256: entry.sha256 };
}

/** 避免为一次 basename 引整个 path 模块（本模块其余部分只需要文件 URL） */
function pathBasename(p) {
  const i = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return i >= 0 ? p.slice(i + 1) : p;
}

/** 该扫描是否启用了解密（热路径上的短路判据） */
export function responseTransformActiveForScan(scanId) {
  return scanId ? registry.has(scanId) : false;
}

/**
 * 对一条已收到的响应施加解密。
 * @param {string} scanId
 * @param {any} res HttpClient 的响应对象（**不会被修改**）
 * @returns {Promise<any>} res 原样返回（未登记时）或 data 被替换后的新对象
 * @throws {AppError} RESPONSE_SCRIPT_FAILED —— 脚本抛错或产出非法形态；调用方按
 *         「该响应不可用」处理（与网络失败同义：记 null、重试/放弃，宁漏不误）
 */
export async function applyResponseTransform(scanId, res) {
  const entry = registry.get(scanId);
  if (!entry) return res;
  const view = {
    status: res?.status,
    headers: res?.headers,
    data: res?.data,
  };
  let out;
  try {
    out = await entry.fn(view);
  } catch (e) {
    throw new AppError(
      ErrorCode.RESPONSE_SCRIPT_FAILED,
      `响应解密脚本执行异常，该响应按失败处理：${e && e.message ? e.message : e}`,
    );
  }
  if (!out || typeof out !== 'object' || Array.isArray(out)) {
    throw new AppError(
      ErrorCode.RESPONSE_SCRIPT_FAILED,
      `响应解密脚本必须返回响应对象，收到 ${out === null ? 'null' : typeof out}，该响应按失败处理`,
    );
  }
  if (out.data === undefined) {
    // 只读不解（例如脚本只想记录）：允许，原样返回
    return res;
  }
  if (typeof out.data !== 'string') {
    throw new AppError(
      ErrorCode.RESPONSE_SCRIPT_FAILED,
      `响应解密脚本返回的 data 必须是字符串，收到 ${typeof out.data}，该响应按失败处理`,
    );
  }
  // 只替换 data：status/headers 是可信度判账的输入，脚本改不了（见文件头约束 3）
  return { ...res, data: out.data };
}

export default {
  assertResponseScriptPath,
  loadResponseScript,
  ensureResponseTransform,
  applyResponseTransform,
  registerResponseTransform,
  releaseResponseTransform,
};
