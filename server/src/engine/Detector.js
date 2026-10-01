import { obfuscateWithConfig } from '../core/tamper/applyTampers.js';
import { buildInjectionRequest } from './injection.js';

// [拆分 2026-10-01] 类体只剩构造器与三个轻量方法；响应相似度/闭合探测/匹配指标/
// 出口发送四大簇物理搬移到 ./detectorSupport/*（函数体逐行原样，由 Detector.prototype
// 挂载，this 语义不变）—— 子类（detectors/*）与测试的调用面、blindExtractor 的
// buildDynamicSimilarGated 导入路径完全不变。
// 顺带下沉的 import：statsHelper（相似度数学）→ similarity.js；echoStrip → boundary.js；
// blockSignatures → matchMetrics.js；egressOpts → matchMetrics.js / egress.js。
export { buildDynamicSimilarFn, buildDynamicSimilarGated } from './detectorSupport/similarity.js';
import { chunkedSimilar, buildDynamicSimilar } from './detectorSupport/similarity.js';
import {
  probeBoundary, _knownPointBoundary, _boundaryBaseline, _boundaryCandidateProbes,
  _boundaryPairDiff, _boundaryOrRecheck, _boundarySimilar,
} from './detectorSupport/boundary.js';
import {
  matchAnchors, _textOnly, matchText, _matchByCode, _toRegExp, _matchByRegexp,
  _extractTitle, _matchByTitle, _matchAnchorsPair, hasExplicitMatch, unusableOf,
  _isWafBlockPage, _pairPollutedByWafBlock, _stripReflected, matchMetrics, _metricLabels,
} from './detectorSupport/matchMetrics.js';
import { send, sendHead, matchNullConnection, _contentLength, sendConcurrent } from './detectorSupport/egress.js';

// 检测器接口/基类（策略模式）
// 子类需实现 detect(ctx)，返回 DetectionResult。
// ctx 约定：{ httpClient, target, point, dbms, config }
export class Detector {
  /**
   * @param {string} technique 检测技术名（union/error/boolean/time）
   */
  constructor(technique) {
    this.technique = technique;
  }

  // 由子类实现具体检测逻辑
  /**
   * 抽象方法：子类必须实现并返回 DetectionResult。
   * 必须显式声明返回类型——否则 TS 按本方法体（只 throw）推断为 Promise<never>，
   * 导致全部子类实现触发 TS2416「返回类型与基类不兼容」。
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('./models.js').DetectionResult>}
   */
  async detect(ctx) {
    throw new Error('Detector.detect 必须由子类实现');
  }

  /**
   * 按注入点位置构造请求对象（注入位置：url/body/cookie/header）
   * @param {object} target 目标
   * @param {object} point 注入点
   * @param {string} injectedValue 注入后的参数值
   */
  buildRequest(target, point, injectedValue) {
    // P1-A3：请求构造三份复制收敛为单一 buildInjectionRequest（injection.js 已完整覆盖
    // direct/url/body/cookie/header + 表单点回退，Detector 不再自建副本）。
    return buildInjectionRequest(target, point, injectedValue);
  }

  /**
   * 按 WAF 规避配置包裹混淆（tamper 链式优先，否则 legacy obfuscate，否则原样）。
   * 统一改调 obfuscateWithConfig，向后兼容：tamper 关且 obfuscate 关时返回原样。
   * @param {object} ctx 检测上下文（含 config.wafEvasion）
   * @param {string} value 已填充的注入值
   * @returns {string} 混淆后（或原样）的注入值
   */
  obfuscateValue(ctx, value) {
    return obfuscateWithConfig(value, ctx);
  }
}

// —— 拆分（2026-10-01）：四大能力簇在原型上按原名挂载（与原类方法同调用风格，this 语义不变）——
Detector.prototype.chunkedSimilar = chunkedSimilar;
Detector.prototype.buildDynamicSimilar = buildDynamicSimilar;
Detector.prototype.probeBoundary = probeBoundary;
Detector.prototype._knownPointBoundary = _knownPointBoundary;
Detector.prototype._boundaryBaseline = _boundaryBaseline;
Detector.prototype._boundaryCandidateProbes = _boundaryCandidateProbes;
Detector.prototype._boundaryPairDiff = _boundaryPairDiff;
Detector.prototype._boundaryOrRecheck = _boundaryOrRecheck;
Detector.prototype._boundarySimilar = _boundarySimilar;
Detector.prototype.matchAnchors = matchAnchors;
Detector.prototype._textOnly = _textOnly;
Detector.prototype.matchText = matchText;
Detector.prototype._matchByCode = _matchByCode;
Detector.prototype._toRegExp = _toRegExp;
Detector.prototype._matchByRegexp = _matchByRegexp;
Detector.prototype._extractTitle = _extractTitle;
Detector.prototype._matchByTitle = _matchByTitle;
Detector.prototype._matchAnchorsPair = _matchAnchorsPair;
Detector.prototype.hasExplicitMatch = hasExplicitMatch;
Detector.prototype.unusableOf = unusableOf;
Detector.prototype._isWafBlockPage = _isWafBlockPage;
Detector.prototype._pairPollutedByWafBlock = _pairPollutedByWafBlock;
Detector.prototype._stripReflected = _stripReflected;
Detector.prototype.matchMetrics = matchMetrics;
Detector.prototype._metricLabels = _metricLabels;
Detector.prototype.send = send;
Detector.prototype.sendHead = sendHead;
Detector.prototype.matchNullConnection = matchNullConnection;
Detector.prototype._contentLength = _contentLength;
Detector.prototype.sendConcurrent = sendConcurrent;

export default Detector;
