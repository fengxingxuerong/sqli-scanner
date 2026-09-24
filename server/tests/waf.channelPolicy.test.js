// waf.channelPolicy.test.js —— A3「通道降级编排」的行为 + 接线验证
// ============================================================================
// 三条主线：
//   ① **纯函数判据**：降级必须极保守（无画像不决策、OR 组内只拦一个不降级、
//      链能消除即不降级、未知技术保留）。
//   ② **画像真的流出来了**：verifyTamperChains 的返回值必须带 `blocked`
//      —— 这是 A3 唯一的输入，带不出来整个编排就是空转。
//   ③ **接线存在**：planChannels 必须在 detect.js 里真被调用
//      （防「helper 写得很全、生产零调用」——本仓已踩过多次）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { planChannels, CHANNEL_TOKENS } from '../src/core/waf/channelPolicy.js';
import { verifyTamperChains } from '../src/core/waf/chainVerify.js';
import { TOKEN_PROBES } from '../src/core/waf/blockProfile.js';

const OK = () => ({ status: 200, data: 'ok page ' + 'x'.repeat(200) });
const BLOCKED = () => ({ status: 403, data: 'blocked' });

// —— ① 纯函数判据 ——

test('无画像（blocked 为空）→ 原样保留全部通道，不做任何决策', () => {
  const techs = ['union', 'error', 'boolean'];
  const out = planChannels({ techniques: techs, blocked: [] });
  assert.deepEqual(out.run, techs, '拿不到证据就不编排（零回归前提）');
  assert.deepEqual(out.skipped, []);
  // 缺省入参同样不决策
  assert.deepEqual(planChannels({ techniques: techs }).run, techs);
  assert.deepEqual(planChannels({ techniques: techs, blocked: null }).run, techs);
});

test('union：union 与 select **都被拦** 才降级（只拦一个不降级）', () => {
  const one = planChannels({ techniques: ['union'], blocked: ['union'] });
  assert.deepEqual(one.run, ['union'], '只拦 union 时仍有 union all→union、大小写等形态');
  const both = planChannels({ techniques: ['union'], blocked: ['union', 'select'] });
  assert.deepEqual(both.run, []);
  assert.equal(both.skipped.length, 1);
  assert.deepEqual(both.skipped[0].deadTokens, ['union', 'select']);
});

test('boolean：与验链探针同形态 → 任何画像都不降级', () => {
  // 画像存在的前提是验链通过（探针「闭合 + AND 表达式」放行），boolean 本身就是这个
  // 形态 → 直接证据优先于记号推断。首版会在这里降级，实测是误杀主力通道。
  for (const blocked of [['and'], ['or'], ['and', 'or'], ['and', 'or', 'quote', 'comment']]) {
    assert.deepEqual(
      planChannels({ techniques: ['boolean'], blocked }).run,
      ['boolean'],
      `boolean 不得因画像 [${blocked.join(',')}] 被降级`
    );
  }
});

test('当前 tamper 链能消除必需记号中的任一 → 不降级', () => {
  // symboliclogical 把 AND/OR 改写为 && / ||；lowercase 消除 union/select 大小写特征
  const bySymbolic = planChannels({
    techniques: ['boolean'],
    blocked: ['and', 'or'],
    covered: ['and', 'or'],
  });
  assert.deepEqual(bySymbolic.run, ['boolean'], '链能消除 → 该通道仍有解，不得降级');

  const byCase = planChannels({
    techniques: ['union'],
    blocked: ['union', 'select'],
    covered: ['union'],
  });
  assert.deepEqual(byCase.run, ['union'], '只消除其中一个也足以保住通道');
});

test('未知技术一律保留（新接入的通道不猜，防"未登记即被降级"）', () => {
  // 用 union 做对照（它此刻会真降级），才能证明「未知技术被保留」不是因为全都没降级
  const out = planChannels({ techniques: ['someNewTech', 'union'], blocked: ['union', 'select'] });
  assert.deepEqual(out.run, ['someNewTech']);
  assert.deepEqual(out.skipped.map((s) => s.technique), ['union']);
});

test('稳定排序：保留的通道保持入参顺序', () => {
  const out = planChannels({
    techniques: ['error', 'union', 'boolean'],
    blocked: ['union', 'select'],
  });
  assert.deepEqual(out.run, ['error', 'boolean'], '仅剔除降级项，不得重排');
});

test('CHANNEL_TOKENS 覆盖全部两层的调度技术（缺一个 = 该通道永远不参与编排）', () => {
  const FAST = ['union', 'error', 'boolean', 'inline'];
  const SLOW = ['time', 'stacked', 'oob'];
  for (const t of [...FAST, ...SLOW]) {
    assert.ok(CHANNEL_TOKENS[t], `CHANNEL_TOKENS 缺少技术 ${t}`);
  }
  // 必需记号必须是真实存在的探针 id（写错即永远不会被拦 → 降级永不触发）
  const ids = new Set(TOKEN_PROBES.map((p) => p.id));
  for (const [tech, spec] of Object.entries(CHANNEL_TOKENS)) {
    for (const group of spec.required) {
      for (const tok of group) assert.ok(ids.has(tok), `${tech} 引用了不存在的探针 id：${tok}`);
    }
  }
});

test('降级对象**恰好**是 union 与 time（扩面必须显式改本条，防偷偷扩大跳过范围）', () => {
  // 依据：画像只在验链通过时才有，而验链探针是「闭合 + 布尔表达式」形态 ——
  // 与探针同形态的通道（error/boolean/inline/stacked/oob）不该被记号画像判死。
  // 与探针**不同形态**、画像才有推断价值的只有 union（集合查询）与 time（延时函数）。
  const degradable = Object.entries(CHANNEL_TOKENS)
    .filter(([, s]) => s.required.length > 0)
    .map(([t]) => t)
    .sort();
  assert.deepEqual(degradable, ['time', 'union'], '降级对象集合变了：请先跑 probe-channel-profile.mjs 复核');
  // required 为空的必须**显式**标 sameShapeAsProbe —— 防「忘了写判据」被当成「永不降级」
  for (const [tech, spec] of Object.entries(CHANNEL_TOKENS)) {
    if (spec.required.length === 0) {
      assert.equal(
        spec.sameShapeAsProbe,
        true,
        `${tech} 的 required 为空却没标 sameShapeAsProbe —— 是「有意不降级」还是「忘了写判据」？`
      );
    }
  }
});

test('CRS 实测画像快照：只降级 union，不得误杀 error/boolean', () => {
  // 画像取自 `node e2e/waf-real/probe-channel-profile.mjs`（crs-engine 真规则执行器，
  // 非 mock）。硬编码快照的价值：把「降级过激」这个已踩过的坑钉死。
  // ⚠️ 若 CRS 规则集/档位变了导致画像变化，本条会红 —— 那时应重跑探针脚本复核，
  // 而不是直接改快照数字。
  const CRS_BLOCKED = ['quote', 'comment', 'or', 'union', 'select', 'sleep', 'cmp'];
  const plan = planChannels({
    techniques: ['union', 'error', 'boolean'],
    blocked: CRS_BLOCKED,
    // 拦截驱动重跑实际使用的算子替换族
    covered: ['and', 'or'],
  });
  assert.deepEqual(plan.run, ['error', 'boolean'], 'CRS 下 error 与 boolean 都必须保留');
  assert.deepEqual(
    plan.skipped.map((s) => s.technique),
    ['union'],
    'CRS 下只应降级 union'
  );
});

// —— ② 画像真的流出来了（端到端，mock 不发真请求）——

const target = { url: 'http://mock.test/?id=1', baseUrl: 'http://mock.test/?id=1', method: 'GET' };
const point = { id: 'p1', location: 'url', param: 'id', originalValue: '1' };

/**
 * 逐词探针识别：与 blockProfile.TOKEN_PROBES 的 value 形态一一对应。
 * ⚠️ 必须锚定 `id=1` 前缀（而不仅是结尾）：整串探针① `1' AND 1=1-- -` 同样以
 * `1-- -` 结尾 —— 只看结尾会把它误判成 comment 探针，于是裸探针永远不会被判
 * "被拦"，画像分支根本进不去（首版即踩：两条端到端用例全红）。
 */
function classifyToken(dec) {
  const table = [
    ['quote', /id=1'$/],
    ['comment', /id=1-- -$/],
    ['hash', /id=1#$/],
    ['space', /id=1 1$/],
    ['and', /id=1 AND 1$/i],
    ['or', /id=1 OR 1$/i],
    ['union', /id=1 UNION 1$/i],
    ['select', /id=1 SELECT 1$/i],
    ['sleep', /id=1 SLEEP\(1\)$/i],
    ['paren', /id=1\(1\)$/],
    ['comma', /id=1,1$/],
    ['cmp', /id=1 1=1$/],
  ];
  for (const [id, re] of table) if (re.test(dec)) return `tok:${id}`;
  return null;
}

function classify(opts) {
  const dec = decodeURIComponent(String(opts.url || '')).replace(/\+/g, ' ');
  const tok = classifyToken(dec);
  if (tok) return tok;
  if (/AND 1=1|AND '1'='1/i.test(dec)) return 'raw'; // 整串探针（明文形态）
  return 'encoded'; // 套了 charencode 后不再是明文 AND
}

test('verifyTamperChains 返回值带出逐词画像（A3 的唯一输入）', async () => {
  const calls = [];
  const client = {
    async request(opts) {
      const kind = classify(opts);
      calls.push(kind);
      if (kind === 'raw') return BLOCKED(); // 裸探针全被拦 → 才会走画像分支
      if (kind === 'tok:union' || kind === 'tok:select') return BLOCKED();
      return OK(); // baseline / 其余探针 / 套链后的探针 → 放行
    },
  };

  const res = await verifyTamperChains({
    httpClient: client,
    target,
    point,
    chains: [{ vendor: 'mock', plugins: ['charencode'] }],
    config: {},
  });

  assert.ok(res, '应返回一条验证通过的链');
  // 不钉死具体插件名：候选池会按画像重排，A2 定向生成的链（如 chardoubleencode）
  // 完全可能顶掉静态链 —— 那是**正确行为**，钉死名字会让这条用例变成噪声。
  assert.ok(Array.isArray(res.plugins) && res.plugins.length > 0, '必须返回非空插件链');
  assert.ok(Array.isArray(res.blocked), '返回值必须带 blocked 字段');
  assert.deepEqual(
    [...res.blocked].sort(),
    ['select', 'union'],
    '画像必须如实反映「union/select 被拦」'
  );
  // 零额外请求：每个探针只发一次（画像没有被重复计算）
  const tokCalls = calls.filter((c) => c.startsWith('tok:'));
  assert.equal(tokCalls.length, TOKEN_PROBES.length, '画像探针恰好一轮，未重复消耗预算');
});

test('未走画像分支（目标不敏感）→ blocked 为空数组，语义是"无证据"', async () => {
  const client = {
    async request() {
      return OK(); // 一切放行 → 裸探针未被拦 → 早退，不画像
    },
  };
  const res = await verifyTamperChains({
    httpClient: client,
    target,
    point,
    chains: [{ vendor: 'mock', plugins: ['charencode'] }],
    config: {},
  });
  assert.deepEqual(res.blocked, [], '未画像时必须是空数组（下游据此不决策）');
});

test('画像 + 链覆盖 → planChannels 得出降级决策（纯函数与端到端拼起来跑得通）', async () => {
  const res = await verifyTamperChains({
    httpClient: {
      async request(opts) {
        const kind = classify(opts);
        if (kind === 'raw') return BLOCKED();
        if (kind === 'tok:union' || kind === 'tok:select') return BLOCKED();
        return OK();
      },
    },
    target,
    point,
    chains: [{ vendor: 'mock', plugins: ['charencode'] }],
    config: {},
  });
  // charencode 覆盖 quote/space/paren/comma/cmp —— 不含 union/select → union 仍应被降级
  const plan = planChannels({
    techniques: ['union', 'error', 'boolean'],
    blocked: res.blocked,
    covered: ['quote', 'space', 'paren', 'comma', 'cmp'],
  });
  assert.deepEqual(plan.run, ['error', 'boolean']);
  assert.deepEqual(plan.skipped.map((s) => s.technique), ['union']);
});

// —— ③ 接线守卫：防 helper 生产零调用 ——

test('接线：detect.js 必须真调用 planChannels（否则整个 A3 是空转）', () => {
  const src = readFileSync(new URL('../src/engine/scan/detect.js', import.meta.url), 'utf8');
  assert.ok(
    /planChannels\s*\(/.test(src),
    'detect.js 未调用 planChannels —— channelPolicy 是纯 helper，生产不调用等于没做'
  );
  // 判据必须是「用画像算出来的」，不能是拿画像当摆设
  assert.ok(
    /blocked:\s*blockedTokens/.test(src),
    'detect.js 调用 planChannels 时必须把逐词画像（blockedTokens）传进去'
  );
  // 安全网：降级后一个通道都不剩时必须回退全集
  assert.ok(
    /plan\.run\.length/.test(src),
    'detect.js 必须具备「降级后无通道可跑 → 回退全集」的判据'
  );
});

test('接线：A3 必须挂进 acceptance 套件（e2e 不接线 = 一次也不会跑）', () => {
  // e2e/waf-real/waf-channel-degrade.e2e.mjs 是 `.e2e.mjs` 而非 `.test.mjs`，
  // 不在 ciWiring 守卫（只管 e2e/**/*.test.mjs）的视野内 —— 它靠 acceptance.mjs
  // 的套件表驱动。故此处补一条源码文本判据，防套件条目被删后无人知晓。
  const src = readFileSync(new URL('../../e2e/acceptance.mjs', import.meta.url), 'utf8');
  assert.ok(
    src.includes('waf-channel-degrade'),
    'acceptance.mjs 未登记 waf-channel-degrade 套件 —— A3 的 e2e 永不会被执行'
  );
});

test('接线：画像只能来自 verifyTamperChains 的返回值（零额外请求）', () => {
  const src = readFileSync(new URL('../src/engine/scan/detect.js', import.meta.url), 'utf8');
  assert.ok(
    /blockedTokens\s*=\s*Array\.isArray\(verifyResult\?\.blocked\)/.test(src),
    'blockedTokens 必须由验链结果赋值，不得另行发一轮画像请求'
  );
  assert.ok(
    !/profileBlockedTokens\s*\(/.test(src),
    'detect.js 不得直接调用 profileBlockedTokens（那会新增一轮探针请求）'
  );
});
