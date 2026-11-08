// ============================================================================
// e2e/ai-gateway-lab/fixture.mjs —— [D276] AI 报告套件的共享 fixture
//
// 为什么抽出来：run.mjs（真网关 / mock 网关共用）与 run-mock.mjs（泄漏断言）必须
// 对**同一份**目标/注入点/漏洞事实做断言。若两份各写一份 fixture，run.mjs 改了
// target 而 run-mock 的泄漏词表没跟着改，泄漏判据会静默失效（扫一个不存在的值）。
//
// 纪律：
//   · scanId 每次变化 ⇒ reportFingerprint 不命中缓存，保证「网关实调」事实成立；
//   · summary 带 verdict / validity / 未验证面 / 未覆盖面 ⇒ D275 的确定性边界章节
//     有真实内容可断言（不是只验 marker 存在）；
//   · FIXTURE_SECRETS 是**脱敏态绝不允许出现在 prompt 里**的原文片段；
//     参数名 `id` / `Submit` 保留（PoC 需要），只禁值与原路径。
// ============================================================================

/** 目标 URL：host、路径、query 值都是脱敏判据的取样点。 */
const FIXTURE_TARGET =
  'http://127.0.0.1:8099/vulnerabilities/sqli/?id=1&Submit=Submit';

/**
 * 脱敏态下不得出现在任何 prompt 里的原文片段。
 * 注意：`127.0.0.1` 只出现在 fixture target，mock 网关自身地址不会进入 prompt。
 * @type {string[]}
 */
export const FIXTURE_SECRETS = [
  '127.0.0.1',
  'vulnerabilities/sqli',
  'id=1',
  'Submit=Submit',
];

/**
 * 最小真形态 fixture：字段 = ReportAI 消费面（target/points/vulns 的
 * poc_payload / poc_verify / evidence）+ D275 边界事实（summary.*）。
 * @returns {object} 可直接传给 generateAiReport 的报告对象
 */
export function makeReport() {
  return {
    scanId: `ai-gateway-fixture-${Date.now()}`,
    startedAt: new Date().toISOString(),
    dbms: 'MySQL',
    target: { baseUrl: FIXTURE_TARGET, method: 'GET' },
    points: [{ param: 'id', location: 'url', originalValue: '1' }],
    summary: {
      verdict: 'vulnerability_detected',
      verdictNote: '检出 1 条 High 风险注入（fixture）',
      validity: { reliable: true, status: 'ok' },
      unverifiedSurfaces: [{
        surface: 'header',
        label: 'HTTP 请求头',
        points: 2,
        tested: 0,
        unverified: 2,
        reason: 'fixture：WAF 拦截',
        sampleParams: ['User-Agent'],
      }],
      uncoveredSurfaces: [{
        surface: 'cookie',
        label: 'Cookie',
        hint: 'fixture：默认 level=1 未覆盖',
      }],
      dbmsEvidence: {
        dbms: 'MySQL',
        level: 'verified',
        levelText: '真实引擎验证',
        caveat: null,
      },
    },
    vulns: [{
      id: 'v1',
      technique: 'boolean',
      parameter: 'id',
      severity: 'High',
      risk: 'High',
      evidence: '真/假探针响应长度差：真样本 1617B / 假样本 30B，首个差异偏移 214',
      poc: { payload: "1' AND '1'='1" },
      poc_payload: "1' AND '1'='1",
      poc_verify: '真/假响应长度差 ≥ 10 倍；状态码 200',
    }],
  };
}
