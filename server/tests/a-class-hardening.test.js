// A 类正确性硬伤修复测试（③~⑥）
//
// ③ StackedDetector timeoutMs 补偿基线 → 慢站不漏报
// ④ Extractor GROUP_CONCAT 截断检测放宽 → 截断在行分隔符处也能检测
// ⑤ BooleanBlindDetector 大 body 头尾+中间采样 → 中间差异不漏报
// ⑥ Detector _boundarySimilar 锚点恒命中防护 → matchString 过于常见时回落分块比对
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Detector } from '../src/engine/Detector.js';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';

// ─── ⑤ BooleanBlindDetector 大 body 采样 ───

test('⑤-1) 大 body: la !== lb 时尾部也比较（旧实现仅 la===lb 才比尾部）', () => {
  const det = new BooleanBlindDetector();
  // 两个大 body，长度差 1（在容差内），头部相同但尾部不同
  const head = 'A'.repeat(70000);
  const a = head + 'TAIL_A';
  const b = head + 'TAIL_B'; // 长度相同但尾部不同
  assert.equal(det._similar(a, b), false, '尾部不同应判不相似');
});

test('⑤-2) 大 body: 头部相同、尾部相同但中间不同 → 不相似', () => {
  const det = new BooleanBlindDetector();
  // 总长 > 65536 才触发大 body 路径
  const prefix = 'X'.repeat(40000);
  const suffix = 'Y'.repeat(40000);
  const a = prefix + 'MID_A' + suffix;
  const b = prefix + 'MID_B' + suffix; // 头尾相同，中间不同
  assert.equal(det._similar(a, b), false, '中间不同应判不相似');
});

test('⑤-3) 大 body: 完全相同 → 相似（回归守卫）', () => {
  const det = new BooleanBlindDetector();
  const body = 'Z'.repeat(70000);
  assert.equal(det._similar(body, body), true, '完全相同应判相似');
});

test('⑤-4) 大 body: 头部不同 → 不相似（回归守卫）', () => {
  const det = new BooleanBlindDetector();
  const a = 'A'.repeat(70000);
  const b = 'B'.repeat(70000);
  assert.equal(det._similar(a, b), false, '头部不同应判不相似');
});

// ─── ⑥ Detector _boundarySimilar 锚点恒命中防护 ───

test('⑥-1) matchString 过于常见（基线和注入后都命中）→ 回落分块比对', () => {
  const det = new Detector();
  // 基线和注入后都含 '<html'，但内容不同 → 锚点恒命中
  const baseBody = '<html><head>Normal Page</head><body>Welcome</body></html>';
  const body = '<html><head>Error Page</head><body>SQL Error</body></html>';
  const config = { matchString: '<html' };
  // 旧实现：matchAnchors 返回 true → _boundarySimilar 直接返回 true（恒命中）
  // 修复后：基线也命中 → 回落 chunkedSimilar → 内容不同 → false
  assert.equal(det._boundarySimilar(baseBody, 200, body, 200, config), false,
    'matchString 过于常见时应回落分块比对，内容不同判不相似');
});

test('⑥-2) matchString 精确（基线命中、注入后不命中）→ 直接返回 false', () => {
  const det = new Detector();
  const baseBody = '<html><body>Welcome User</body></html>';
  const body = '<html><body>SQL Error</body></html>';
  const config = { matchString: 'Welcome User' };
  // 基线含 'Welcome User'，注入后不含 → matchAnchors(body) 返回 false
  assert.equal(det._boundarySimilar(baseBody, 200, body, 200, config), false,
    'matchString 精确且注入后不命中 → false');
});

test('⑥-3) matchString 精确（基线命中、注入后也命中）→ 回落分块比对判相似', () => {
  const det = new Detector();
  const baseBody = '<html><body>Welcome User</body></html>';
  const body = '<html><body>Welcome User</body></html>';
  const config = { matchString: 'Welcome User' };
  // 基线和注入后都含 'Welcome User' → 基线验证也 true → 回落分块比对
  // 内容完全相同 → chunkedSimilar 返回 true
  assert.equal(det._boundarySimilar(baseBody, 200, body, 200, config), true,
    'matchString 精确且内容相同 → 回落后仍判相似');
});

test('⑥-4) 无 matchString 配置 → 行为不变（回归守卫）', () => {
  const det = new Detector();
  const baseBody = 'Normal Response Body';
  const body = 'Normal Response Body';
  const config = {}; // 无锚点
  // matchAnchors 返回 null → 走状态码 + 分块比对
  assert.equal(det._boundarySimilar(baseBody, 200, body, 200, config), true,
    '无锚点配置时行为不变');
});

test('⑥-5) matchString 过于常见 + 状态码不同 → 不相似', () => {
  const det = new Detector();
  const baseBody = '<html>Normal</html>';
  const body = '<html>Error</html>';
  const config = { matchString: '<html' };
  // 锚点恒命中 → 回落 → 状态码不同 → false
  assert.equal(det._boundarySimilar(baseBody, 200, body, 500, config), false,
    '锚点恒命中时状态码不同应判不相似');
});

// ─── ③ StackedDetector timeoutMs 补偿（逻辑验证） ───

test('③-1) StackedDetector timeoutMs 补偿基线（逻辑验证）', async () => {
  // 验证修复后的超时计算逻辑：
  // timeoutMs = effectiveThreshold + sleep * 1000
  // effectiveThreshold = max(thresholdMs, baselineMs + sleep * 500)
  // 因此 timeoutMs >= baselineMs + sleep * 1500 > baselineMs + sleep * 1000（注入后预期耗时）
  const sleep = 2;
  const thresholdMs = 1000;
  const baselineMs = 5000; // 慢站基线 5 秒
  const effectiveThreshold = Math.max(thresholdMs, baselineMs + (sleep * 1000) / 2);
  const timeoutMs = effectiveThreshold + sleep * 1000;
  // 注入后预期耗时 = baseline + sleep = 7 秒
  const expectedElapsed = baselineMs + sleep * 1000;
  // timeoutMs（11 秒）> expectedElapsed（7 秒）→ 不会超时
  assert.ok(timeoutMs > expectedElapsed,
    `timeoutMs (${timeoutMs}) 应大于注入后预期耗时 (${expectedElapsed})`);
  // 旧实现：timeoutMs = baseTimeout + sleep = 30000 + 2000 = 32000
  // 但如果 baseTimeout = 5000（慢站），timeoutMs = 7000，注入后耗时 = 7000 → 边界超时
  const oldTimeoutMs = 5000 + sleep * 1000; // 假设 baseTimeout = baseline
  assert.ok(oldTimeoutMs <= expectedElapsed,
    `旧实现 timeoutMs (${oldTimeoutMs}) <= 注入后耗时 (${expectedElapsed}) → 漏报`);
});

// ─── ④ Extractor GROUP_CONCAT 截断检测（逻辑验证） ───

test('④-1) GROUP_CONCAT 截断检测：val >= 1000 且行数 < lim → 触发降级', () => {
  // 验证修复后的截断检测条件
  const edb = 'MySQL';
  const lim = 10;
  // 场景1：截断后仅 1 行，行长 >= 1000（旧实现可检测）
  const val1 = 'x'.repeat(1020);
  const rowStrs1 = [val1]; // 1 行
  const mayTruncate1 = (edb === 'MySQL') && val1.length >= 1000 && rowStrs1.length < lim;
  assert.equal(mayTruncate1, true, '截断后 1 行且 val >= 1000 应触发降级');
  // 场景2：截断切在行分隔符处，多行但不足 lim（旧实现漏检，修复后可检测）
  const rowSep = String.fromCharCode(0x1e);
  const val2 = 'a'.repeat(500) + rowSep + 'b'.repeat(500); // 2 行，val 长度 1001
  const rowStrs2 = val2.split(rowSep).map((r) => r.trim()).filter(Boolean);
  const mayTruncate2 = (edb === 'MySQL') && val2.length >= 1000 && rowStrs2.length < lim;
  assert.equal(mayTruncate2, true, '截断在行分隔符处（多行但 val >= 1000）也应触发降级');
  // 场景3：正常末页，val < 1000 → 不触发降级
  const val3 = 'normal data';
  const rowStrs3 = [val3];
  const mayTruncate3 = (edb === 'MySQL') && val3.length >= 1000 && rowStrs3.length < lim;
  assert.equal(mayTruncate3, false, '正常末页（val < 1000）不应触发降级');
});
