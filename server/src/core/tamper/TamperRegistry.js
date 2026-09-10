import { ErrorCode, AppError } from '../errors.js';
import { logger } from '../logger.js';

// tamper 插件注册表（策略模式容器）
// 对标 sqlmap --tamper：把"单一内联混淆"升级为"链式可插拔"体系。
// 内置插件在 applyTampers.js 导入时注册；用户插件可按名注册后由 config.wafEvasion.tamper.plugins 引用。
export class TamperRegistry {
  constructor() {
    // name -> 插件对象 { name, description, transform(payload, ctx) }
    this._plugins = new Map();
  }

  /**
   * 注册单个插件
   * @param {{name:string, description?:string, transform:(payload:string, ctx:object)=>string}} plugin
   * @returns {TamperRegistry} 便于链式
   * @throws {AppError} 缺 name 抛 TAMPER_INVALID_NAME
   */
  register(plugin) {
    if (!plugin || typeof plugin.name !== 'string' || !plugin.name) {
      throw new AppError(ErrorCode.TAMPER_INVALID_NAME, 'tamper 插件必须包含唯一 name 字段');
    }
    if (typeof plugin.transform !== 'function') {
      throw new AppError(ErrorCode.TAMPER_INVALID_NAME, `tamper 插件 ${plugin.name} 必须实现 transform 函数`);
    }
    this._plugins.set(plugin.name, plugin);
    return this;
  }

  /**
   * 批量注册插件（启动期注册内置 + 用户插件）
   * @param {Array} plugins
   * @returns {TamperRegistry}
   */
  registerMany(plugins = []) {
    for (const p of plugins || []) this.register(p);
    return this;
  }

  /**
   * 按名取插件
   * @param {string} name
   * @returns {object|null}
   */
  get(name) {
    return this._plugins.get(name) || null;
  }

  /**
   * 列出全部插件元信息（不含 transform，便于序列化展示）
   * @returns {Array<{name:string, description:string, dbms?:string[], terminal?:boolean}>}
   */
  list() {
    return [...this._plugins.values()].map((p) => ({
      name: p.name,
      description: p.description || '',
      ...(Array.isArray(p.dbms) && p.dbms.length ? { dbms: [...p.dbms] } : {}),
      ...(p.terminal ? { terminal: true } : {}),
      // [P0 2026-09-09] 幂等声明透出（tamper.idempotency.test.js 守卫：
      // 声明 idempotent:true 的插件必须满足 f(f(x)) === f(x)，链式/重跑不损坏 payload）
      ...(p.idempotent === true ? { idempotent: true } : {}),
    }));
  }

  /**
   * 列出全部插件原始对象（含 transform / doctests，供快照回归与组合演练）
   * @returns {Array}
   */
  all() {
    return [...this._plugins.values()];
  }

  /**
   * 按名数组解析成有序插件数组（未知名跳过并告警，保证链式顺序由数组顺序决定）
   *
   * [P1-FIX 2026-09-05] 串联静态校验（消费插件可选元数据）：
   *   - `dbms: ['MySQL',...]`：目标 dbms 已知且不在列表 → 跳过该插件并告警
   *     （防 dollarquote(仅 PG)/sleep2getlock(仅 MySQL)/percentage(仅 ASP) 被套到异构库
   *      静默产出无效 payload——sqlmap 官方 tamper 自带 dbms 声明）；
   *   - `terminal: true`：该插件输出形态固定（如 base64encode/charencode 全编码），
   *     其后所有插件全部空转 → 截断并告警（修复 base64encode→space2comment 静默空转）。
   * ctx.dbms 未提供时不做 dbms 过滤（保守，不影响既有调用方）。
   * @param {string[]} names
   * @param {{dbms?:string}} [ctx] 检测上下文（dbms 可选）
   * @returns {Array}
   */
  resolve(names = [], ctx = {}) {
    const resolved = [];
    let truncated = false;
    // [P0 2026-09-09] 显式声明 idempotent:false 的插件在链中重复出现 → 告警：
    // 非幂等插件二次应用必然损坏 payload（f(f(x)) !== f(x)），
    // 「被 WAF 拦后重跑」场景会把损坏形态发给目标，实测即假阴性 + 噪声请求。
    const seenNonIdempotent = new Set();
    const dupWarned = new Set();
    for (const n of names || []) {
      const p = this._plugins.get(n);
      if (!p) {
        logger.warn(`tamper 插件未找到：${n}（已跳过）`);
        continue;
      }
      if (p.idempotent === false) {
        if (seenNonIdempotent.has(n) && !dupWarned.has(n)) {
          logger.warn(`tamper 链中非幂等插件 ${n} 重复出现：二次应用会损坏 payload（f(f(x))≠f(x)），请确认链配置`);
          dupWarned.add(n);
        }
        seenNonIdempotent.add(n);
      }
      if (truncated) {
        logger.warn(`tamper 链已因 ${resolved[resolved.length - 1]?.name}（terminal）截断，跳过：${n}`);
        continue;
      }
      if (Array.isArray(p.dbms) && p.dbms.length && ctx.dbms) {
        const target = String(ctx.dbms).toLowerCase();
        const hit = p.dbms.some((d) => {
          const dNorm = String(d).toLowerCase();
          return target === dNorm || (dNorm === 'mssql' && target === 'sql server');
        });
        if (!hit) {
          // 对齐 sqlmap：dbms 限定不符仅告警不截断（保留用户显式意志，打破"静默产出无效 payload"）
          logger.warn(`tamper ${n} 仅适用于 [${p.dbms.join(',')}]，目标 ${ctx.dbms} 不匹配（仍然应用）`);
        }
      }
      resolved.push(p);
      if (p.terminal) truncated = true;
    }
    return resolved;
  }

  /**
   * 静态链校验（不发请求，供 UI/API 在用户选链时预检）
   * @param {string[]} names
   * @param {{dbms?:string}} [ctx]
   * @returns {{ok:boolean, warnings:string[], plugins:string[]}}
   */
  validateChain(names = [], ctx = {}) {
    const warnings = [];
    const kept = [];
    let truncated = false;
    for (const n of names || []) {
      const p = this._plugins.get(n);
      if (!p) {
        warnings.push(`未注册的插件：${n}`);
        continue;
      }
      if (truncated) {
        warnings.push(`${n} 位于 terminal 插件之后，将被截断（输出形态已固定，后续变换无效）`);
        continue;
      }
      if (Array.isArray(p.dbms) && p.dbms.length && ctx.dbms) {
        const target = String(ctx.dbms).toLowerCase();
        const hit = p.dbms.some((d) => {
          const dNorm = String(d).toLowerCase();
          return target === dNorm || (dNorm === 'mssql' && target === 'sql server');
        });
        if (!hit) {
          warnings.push(`${n} 仅适用于 [${p.dbms.join(',')}]，目标 ${ctx.dbms} 不匹配（仍将应用，建议确认）`);
        }
      }
      kept.push(n);
      if (p.terminal) truncated = true;
    }
    return { ok: warnings.length === 0 && kept.length > 0, warnings, plugins: kept };
  }
}

// 单例：全应用共享同一注册表
export const tamperRegistry = new TamperRegistry();
export default tamperRegistry;
