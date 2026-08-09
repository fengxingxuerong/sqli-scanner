import { logger } from './logger.js';

/**
 * 安全间隔探测客户端（装饰器，对标 sqlmap --safe-url / --safe-freq / 多 safe-url 随机轮询）。
 *
 * 包裹真实 httpClient：每累计发出 safeFreq 次真实请求，穿插一次"安全 URL"探测
 * （确信不含注入副作用、始终应返回稳定内容的页面），与扫描开始时抓取的基线比对。
 * 一旦偏离（被 WAF/IPS 拦截、会话失效、限流、内容被替换），通过 onAnomaly 回调告警，
 * 提示当前批次的检测结果可能失真。默认不阻断主扫描（与 sqlmap 行为一致：只告警）。
 *
 * 多安全 URL（随机轮询，隐蔽增强）：支持传入多个 safe-url（逗号分隔 / urls 数组）。
 * 每次探测随机挑选一个访问（默认 randomize=true），避免 WAF 把"固定 safe-url 模式"关联到扫描；
 * 也可 --safe-order 关闭随机、顺序轮询。每个 URL 独立抓基线、独立比对，
 * 单个 URL 基线抓取失败仅禁用该 URL，不影响其他 URL 的探测。
 *
 * 未配置 safeUrl/safeUrls 或 safeFreq<=0 时完全透传，对现有行为零侵入。
 */
export class SafeProbeClient {
  /**
   * @param {object} inner 真实 httpClient（需暴露 request 方法）
   * @param {object} opts { safeUrl, safeUrls, safeFreq, randomize, onAnomaly, onProbe, tolerance }
   *   - safeUrl: 单个安全 URL 字符串（向后兼容）
   *   - safeUrls: 多个安全 URL 数组（逗号分隔 / 数组均可；与 safeUrl 合并去重）
   *   - safeFreq: 每 N 次真实请求穿插一次探测（>=1 启用）
   *   - randomize: 多 URL 时是否随机选（默认 true；false=顺序轮询）
   *   - onAnomaly: (info) => void  偏离回调（info: { url, reason, baseline, actual }）
   *   - onProbe: (info) => void 每次探测记录（info: { url, ok, elapsedMs }）
   *   - tolerance: { lenRatio, lenAbs } 体长偏离容忍（默认 0.3 / 200）
   */
  constructor(inner, opts = {}) {
    this.inner = inner;
    // 合并 safeUrl(safeUrls) 去重，统一为数组（向后兼容单 safeUrl）
    const raw = [];
    if (opts.safeUrl) raw.push(opts.safeUrl);
    if (Array.isArray(opts.safeUrls)) raw.push(...opts.safeUrls);
    const seen = new Set();
    this.safeUrls = [];
    for (const u of raw) {
      if (typeof u === 'string' && u.trim()) {
        const t = u.trim();
        if (!seen.has(t)) { seen.add(t); this.safeUrls.push(t); }
      }
    }
    this.safeUrl = this.safeUrls[0] || null; // 兼容旧调用/日志（取第一个）
    this.safeFreq = Number(opts.safeFreq) > 0 ? Number(opts.safeFreq) : 0;
    this.randomize = opts.randomize !== false; // 默认随机选 URL
    this.onAnomaly = typeof opts.onAnomaly === 'function' ? opts.onAnomaly : null;
    this.onProbe = typeof opts.onProbe === 'function' ? opts.onProbe : null;
    this.tolerance = opts.tolerance || { lenRatio: 0.3, lenAbs: 200 };
    this.enabled = this.safeUrls.length > 0 && this.safeFreq >= 1;
    this.count = 0;
    this.rrIdx = 0; // 顺序轮询游标
    // 每个 URL 独立基线（懒抓）+ 初始化标记 + 失败禁用标记
    this.baselines = new Map(); // url -> { status, body }
    this._baselineInit = new Set(); // 已抓过基线的 url
    this._baselineFailed = new Set(); // 基线抓取失败的 url（永久禁用该 url）
  }

  // 从候选池选一个本次探测的 URL：随机（默认）或顺序轮询（--safe-order）
  _pickUrl() {
    const avail = this.safeUrls.filter((u) => !this._baselineFailed.has(u));
    if (avail.length === 0) return null;
    if (this.randomize) {
      return avail[Math.floor(Math.random() * avail.length)];
    }
    // 顺序轮询：在可用池内按 rrIdx 取下一个
    const url = avail[this.rrIdx % avail.length];
    this.rrIdx += 1;
    return url;
  }

  // 抓取指定 URL 的基线（懒抓：首次用到该 URL 时抓，避免依赖调用方初始化顺序）
  async _ensureBaseline(url) {
    if (this._baselineInit.has(url) || this._baselineFailed.has(url)) return;
    this._baselineInit.add(url);
    try {
      const t0 = Date.now();
      const res = await this.inner.request({ method: 'GET', url, timeoutMs: 8000 });
      this.baselines.set(url, {
        status: res?.status ?? 0,
        body: String(res?.data ?? ''),
      });
      logger.info(
        `安全探测基线已抓取（${url}）：status=${res?.status ?? 0}, len=${String(res?.data ?? '').length}`
      );
      if (this.onProbe) {
        this.onProbe({ url, ok: true, elapsedMs: Date.now() - t0, baseline: true });
      }
    } catch (e) {
      // 该 URL 基线抓取失败：仅禁用该 URL（其他 URL 仍可用），并标记失败避免反复误报
      logger.warn(`安全探测基线抓取失败（${url}），禁用该安全 URL：${e.message}`);
      this._baselineFailed.add(url);
      this.enabled = this.safeUrls.some((u) => !this._baselineFailed.has(u)) && this.safeFreq >= 1;
    }
  }

  // 发起一次安全探测（随机/轮询选 URL）并与该 URL 自身基线比对；偏离则回调告警。返回是否异常。
  async _probe() {
    if (!this.enabled) return false;
    const url = this._pickUrl();
    if (!url) return false; // 无可用 URL（全部基线失败）→ 跳过
    await this._ensureBaseline(url);
    const base = this.baselines.get(url);
    if (!base) return false; // 该 URL 基线未就绪（抓取失败已被禁用）→ 跳过
    const t0 = Date.now();
    try {
      const res = await this.inner.request({ method: 'GET', url, timeoutMs: 8000 });
      const actual = { status: res?.status ?? 0, body: String(res?.data ?? '') };
      const ok = this._compare(base, actual);
      if (this.onProbe) {
        this.onProbe({ url, ok, elapsedMs: Date.now() - t0, baseline: false });
      }
      if (!ok && this.onAnomaly) {
        this.onAnomaly({
          url,
          reason: this._reason(base, actual),
          baseline: base,
          actual,
        });
      }
      return !ok;
    } catch (e) {
      // 安全探测本身失败：也视为异常信号（目标可能对安全 URL 也限流/拦截）
      logger.warn(`安全探测请求失败（${url}）：${e.message}`);
      if (this.onProbe) this.onProbe({ url, ok: false, elapsedMs: Date.now() - t0, error: e.message });
      if (this.onAnomaly) {
        this.onAnomaly({ url, reason: `safe-url 探测异常：${e.message}`, baseline: base, actual: null });
      }
      return true;
    }
  }

  // 比对基线与实际：status 不同 → 异常；体长偏离容忍带 → 异常
  _compare(base, actual) {
    if (base.status !== actual.status) return false;
    const bl = base.body.length;
    const al = actual.body.length;
    const diff = Math.abs(al - bl);
    // 容忍：相对比例 与 绝对字节 任一在容忍内即不算偏离
    const ratioOk = bl > 0 ? diff / bl <= this.tolerance.lenRatio : al === 0;
    const absOk = diff <= this.tolerance.lenAbs;
    return ratioOk && absOk;
  }

  _reason(base, actual) {
    if (base.status !== actual.status) {
      return `安全 URL 状态码偏离：基线 ${base.status} → 实际 ${actual.status}`;
    }
    return `安全 URL 响应体长度偏离基线：${base.body.length} → ${actual.body.length}`;
  }

  // 透传接口（供 Detector.send / sendConcurrent 调用，与真实 httpClient 同签名）
  async request(opts) {
    this.count += 1;
    // 穿插安全探测：每 safeFreq 次真实请求前先探一次（基线就绪后）
    if (this.enabled && this.safeFreq >= 1 && this.count % this.safeFreq === 0) {
      await this._probe();
    }
    return this.inner.request(opts);
  }
}

export default SafeProbeClient;
