// 统计辅助工具（纯函数，零依赖）
// 用于盲注判定鲁棒性：基线分布感知（μ + z·σ）+ 一致率统计，抗网络抖动/服务端动态内容误判。

// 均值；空数组返回 0
export function mean(arr) {
  if (!arr || arr.length === 0) return 0;
  let sum = 0;
  for (const v of arr) sum += v;
  return sum / arr.length;
}

// 总体标准差（population std）；长度 < 2 返回 0
export function std(arr) {
  if (!arr || arr.length < 2) return 0;
  const m = mean(arr);
  let acc = 0;
  for (const v of arr) {
    const d = v - m;
    acc += d * d;
  }
  return Math.sqrt(acc / arr.length);
}

// 布尔数组为 true 的比例；空数组返回 0
export function ratioTrue(flags) {
  if (!flags || flags.length === 0) return 0;
  let n = 0;
  for (const f of flags) if (f) n++;
  return n / flags.length;
}

// 一致率：对每个 response 计算 match = (similarFn(response) === expected)，返回 match 占比。
// similarFn 由检测器注入（闭包封装其 _similarToBaseline + baselines）。
export function similarityRate(responses, similarFn, expected) {
  if (!responses || responses.length === 0) return 0;
  let hits = 0;
  for (const r of responses) {
    if (similarFn(r) === expected) hits++;
  }
  return hits / responses.length;
}

// 分布感知阈值：σ>0 用 μ+z·σ；σ=0（含基线零抖动/纯 mock）退化为 μ+absFloor（= legacy 固定阈值）
export function effectiveThreshold(mu, sigma, z, absFloor) {
  if (sigma > 0) return mu + z * sigma;
  return mu + absFloor;
}

// 基线自然抖动率（"噪声地板"）：基线响应两两比较，不相似对占比。
// similarFn(a,b) 由检测器注入（封装其相似判定）。样本 < 2 返回 0。
export function baselineNoiseRate(responses, similarFn) {
  if (!responses || responses.length < 2) return 0;
  const n = responses.length;
  const pairs = (n * (n - 1)) / 2;
  let diff = 0;
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      if (!similarFn(responses[i], responses[j])) diff++;
    }
  }
  return pairs ? diff / pairs : 0;
}

// 自适应一致率门槛：要求信号清晰程度超过目标自身噪声 + 余量，再夹在 [floor, cap] 内。
// 稳定目标(noise≈0) → 落回 floor（保持严格，控误报）；抖动目标(noise 大) → 抬高门槛（要求更明确的信号）。
export function adaptiveMinStable(noise, headroom, floor, cap) {
  const raw = (noise || 0) + (headroom || 0);
  return Math.min(cap, Math.max(floor, raw));
}

// 时间盲注自适应绝对下限：在固定阈值基础上，按基线抖动 σ 线性放宽，抑制微抖动误报。
// σ≈0（稳定目标）→ floor=absFloor（与现状一致）；σ 大（抖动目标）→ floor 更宽（更难误报）。
export function adaptiveTimeFloor(absFloor, sigma, scale = 2) {
  return (absFloor || 0) + (scale || 0) * (sigma || 0);
}

// 两比例 z 检验：判断"注入引起的变化率"是否显著高于"基线自然抖动率"（抗误报）。
// rateA/nA = 观测组（如 false 条件响应偏离基线的比例与样本数）；
// rateB/nB = 对照组（如基线两两自比较的差异比例与配对对数）。
// 返回 z 分数（单侧用，正值=观测组显著高于对照组）。
// 分母不足（nA<1 或 nB<1）或合并比例标准误为 0 时返回 null（无法确定显著性，保守处理为"不显著"）。
export function twoProportionZ(rateA, nA, rateB, nB) {
  if (!(nA >= 1) || !(nB >= 1)) return null;
  const total = nA + nB;
  if (total < 2) return null;
  const pA = Math.min(1, Math.max(0, rateA));
  const pB = Math.min(1, Math.max(0, rateB));
  const pPool = (pA * nA + pB * nB) / total;
  const se = Math.sqrt(pPool * (1 - pPool) * (1 / nA + 1 / nB));
  if (se === 0) return null;
  return (pA - pB) / se;
}

// 显著性判定（单侧）：z > 临界值即视为"观测变化显著超过自然抖动"。
// 默认 95% 单侧 zCrit=1.645；z 为 null（无法确定）时保守返回 false（不声明显著，避免误报）。
export function isSignificant(rateA, nA, rateB, nB, zCrit = 1.645) {
  const z = twoProportionZ(rateA, nA, rateB, nB);
  if (z === null) return false;
  return z > zCrit;
}
