// ============================================================================
// configNested.guard.test.js —— 嵌套配置（noSql / oob / secondOrder）的
// 「面板形状 → sanitizeStart 逐字段保留」契约
// ============================================================================
// 为什么单独一支（而不是并进 configReachability.guard.test.js）：
// 那支管的是**顶层标量键**的可达性（CLI 写的键 ∩ 引擎读的键 − REST 白名单）。
// 而这三个键是**嵌套对象**：白名单里出现它们的名字，不等于子字段能活下来 ——
// sanitizeStart 对每个子字段单独 clamp，字段名拼错 / 类型给错 / 越界，都会
// **静默回落到默认值**。后果与顶层键被丢弃一模一样：用户在面板上填了回调地址、
// 勾了写确认位，引擎跑的仍是默认配置，报告只写「未检出」—— 静默假阴性。
//
// 2026-09-23 实测背景（本支测试就是被这三件事逼出来的）：
//   ① `noSql` 登记在 SCAN_CONFIG_KEYS 里，被契约测试判为「已有 UI 入口」→ 假绿；
//      实际面板从未渲染它 → NoSQL/GraphQL/SSTI 整条通道界面用户永远开不了。
//   ② `oob` 的总开关此前 UI 无入口，而它是**独立总开关**（techniques 里勾了 oob 也不够）。
//   ③ `secondUrl` / `secondMethod` / `secondData`（读写分离二阶注入）——
//      引擎在 SecondOrderDetector._trigger 里真读它们，但 REST clamp 不保留、CLI 无处可设
//      → 与 extractScope 同一病灶：能力在，入口不在。
//   这三处都没有任何测试看住它们的**子字段**，所以本支测试同时充当「前后端字段名一致性」契约。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { sanitizeStart } from '../src/api/scanRoutes.js';

const HERE = fileURLToPath(import.meta.url);
const SERVER = path.resolve(HERE, '..', '..');
const read = (rel) => readFileSync(path.join(SERVER, rel), 'utf8');

const START_URL = 'http://127.0.0.1:8273/products/list.php?id=1';
const cfgOf = (config) => sanitizeStart({ url: START_URL, config }).config;

test('自证：sanitizeStart 真被调用到了（否则下面所有断言都会空转全绿）', () => {
  const out = cfgOf({ level: 3, testPath: true });
  assert.equal(out.level, 3, '已知标量键必须先能落地，否则说明调用姿势错了');
  assert.equal(out.testPath, true);
  // 注意（首版断言在这里写错、被本测试自己抓出来）：
  // sanitizeStart **不注入未传的键** —— 它只处理请求里出现的字段，默认值由引擎侧
  // defaults.js 在 ScanManager 里合并。所以「没传 oob」时 config.oob 就是 undefined，
  // 而不是一份默认配置对象。显式传了才走 clamp 分支。
  assert.equal(cfgOf({}).oob, undefined, '未传 oob 时不应凭空注入（默认值由引擎侧合并）');
  assert.equal(typeof cfgOf({ oob: { enabled: true } }).oob, 'object', '显式传 oob 时应得到 clamp 后的对象');
});

test('契约：noSql —— 面板的开关与类别选择逐项落地', () => {
  const out = cfgOf({ noSql: { enabled: true, kinds: ['nosql', 'ssti'] } }).noSql;
  assert.equal(out.enabled, true, 'noSql.enabled 必须落地（它是这条补充趟的门控）');
  assert.deepEqual(out.kinds, ['nosql', 'ssti'], 'kinds 应原样落地（顺序也不该被重排）');

  // 反向：非法类别被逐个剔除，合法项保留（不能整包丢弃）
  assert.deepEqual(
    cfgOf({ noSql: { enabled: true, kinds: ['nosql', 'sqli', 'graphql'] } }).noSql.kinds,
    ['nosql', 'graphql'],
    '非法 kind 应被过滤，合法项必须留下'
  );

  // 空数组语义：后端 clamp 结果为空，引擎侧（ScanManager:627）按「全部类别」兜底 ——
  // 面板的提示文案就是按这条行为写的，此处把它钉住，避免有人"顺手"改成空数组=不跑。
  assert.deepEqual(cfgOf({ noSql: { enabled: true, kinds: [] } }).noSql.kinds, []);

  // 关掉总开关时后端不得自作主张打开
  assert.equal(cfgOf({ noSql: { enabled: false, kinds: ['nosql'] } }).noSql.enabled, false);
});

test('契约：oob —— 面板填的每个子字段都要活到引擎（拼错一个字段名 = 白填）', () => {
  const sent = {
    enabled: true,
    callbackBase: 'oob.example.com:9000',
    httpPort: 9000,
    timeoutMs: 8000,
    dnsOob: true,
    dnsDomain: 'dns.example.com',
    dnsPort: 5353,
  };
  const out = cfgOf({ oob: sent }).oob;
  for (const [k, v] of Object.entries(sent)) {
    assert.equal(out[k], v, `oob.${k} 未原样落地 —— 前端字段名与后端 clamp 已不一致（面板会显示已配置、引擎却用默认值）`);
  }

  // 反向：越界值必须被夹进合法区间，而不是带病进引擎（端口 0 / 超长域名都会让接收端起不来）。
  // ⚠️ 实测行为是**夹到边界**（clampInt 的语义），不是回落到默认值 —— 首版断言按「回落」写、
  // 被本测试自己抓出来（httpPort:0 得到 1 而不是 8899）。这里按真实行为钉住：
  assert.equal(cfgOf({ oob: { enabled: true, httpPort: 0 } }).oob.httpPort, 1, '端口 0 应被夹到下限 1');
  assert.equal(cfgOf({ oob: { enabled: true, dnsPort: 70000 } }).oob.dnsPort, 65535, '越界 dnsPort 应被夹到上限');
  assert.equal(cfgOf({ oob: { enabled: true, timeoutMs: 999999 } }).oob.timeoutMs, 60000, 'timeoutMs 应被夹到上限');
  assert.equal(cfgOf({ oob: { enabled: true, timeoutMs: 1 } }).oob.timeoutMs, 1000, 'timeoutMs 应被夹到下限');
  assert.equal(cfgOf({ oob: { enabled: true, dnsDomain: 'a'.repeat(300) } }).oob.dnsDomain.length, 253, 'dnsDomain 应截到 RFC 上限 253');
  // 非数字垃圾值才回落默认（与上面「数字越界夹边界」是两条不同分支）
  assert.equal(cfgOf({ oob: { enabled: true, httpPort: 'abc' } }).oob.httpPort, 8899, '非数字端口应回落默认值');

  // 面板只开总开关、不给子字段：必须回落默认值，而不是 undefined 进引擎
  const minimal = cfgOf({ oob: { enabled: true } }).oob;
  assert.equal(minimal.callbackBase, '127.0.0.1:8899');
  assert.equal(minimal.dnsOob, false);
  assert.equal(minimal.dnsDomain, '');
});

test('契约：secondOrder —— 触发页、写确认位、读写分离字段逐项落地', () => {
  const sent = {
    enabled: true,
    triggerUrls: ['https://t.example.com/profile'],
    refreshCsrf: false,
    negativeControl: false,
    oobTrigger: true,
    allowWrites: true,
    secondUrl: 'https://t.example.com/read',
    secondMethod: 'POST',
    secondData: 'a=1&b=2',
  };
  const out = cfgOf({ secondOrder: sent }).secondOrder;
  assert.equal(out.enabled, true);
  assert.deepEqual(out.triggerUrls, ['https://t.example.com/profile']);
  assert.equal(out.refreshCsrf, false, '显式 false 必须照发（关掉 CSRF 重抓是一个动作）');
  assert.equal(out.negativeControl, false);
  assert.equal(out.oobTrigger, true);
  // ★ 写确认位：丢了它，生产护栏下二阶请求一律被拦 → 「开了二阶却永远未检出」
  assert.equal(out.allowWrites, true, 'allowWrites 必须落地');
  // ★ 读写分离三字段（2026-09-23 修复的可达性缺口）
  assert.equal(out.secondUrl, 'https://t.example.com/read', 'secondUrl 必须落地（引擎按它决定读取发往哪里）');
  assert.equal(out.secondMethod, 'POST');
  assert.equal(out.secondData, 'a=1&b=2');

  // 反向：非 http(s) 的 secondUrl 不得进引擎（SSRF 面的第一道形状闸门）
  for (const bad of ['ftp://x/a', 'javascript:alert(1)', 'file:///etc/passwd', '/relative']) {
    assert.equal(cfgOf({ secondOrder: { enabled: true, secondUrl: bad } }).secondOrder.secondUrl, '', `secondUrl=${bad} 不该被接受（应清空回退触发页）`);
  }

  // 反向：allowWrites 必须是严格 true（引擎/sanitize 都按 === true 判定）
  for (const bad of [1, 'true', {}, [], 'yes']) {
    assert.equal(
      cfgOf({ secondOrder: { enabled: true, allowWrites: bad } }).secondOrder.allowWrites,
      false,
      `allowWrites=${JSON.stringify(bad)} 不该被当成「已确认写请求」`
    );
  }

  // 面板只开总开关时：两个默认为 true 的项保持 true，triggerUrls 为空数组（不为 undefined）
  const minimal = cfgOf({ secondOrder: { enabled: true } }).secondOrder;
  assert.equal(minimal.refreshCsrf, true);
  assert.equal(minimal.negativeControl, true);
  assert.deepEqual(minimal.triggerUrls, []);
});

test('安全：secondUrl 必须与触发页同级受 SSRF / 授权范围校验（源码级守卫）', () => {
  // sanitizeStart 只能做形状过滤（同步函数不能 await）；真正的 assertSafeHttpTarget
  // 在 /scan/start handler 的 async 层。这条断言用源码文本钉住那段逻辑存在 ——
  // 否则「以后重构顺手删掉」会让 secondUrl 变成一条绕过 scope 的内网读取通道，
  // 而单测全绿（因为 sanitizeStart 层看不出差别）。
  const src = read('src/api/scanRoutes.js');
  // 锚点用赋值语句本身，不用注释文案里的字：warn 文案里也含「二阶读取页」，
  // 用文案定位会把切片起点落到 warn 之后，于是 assertSafeHttpTarget 刚好被切掉 → 假红。
  const segStart = src.indexOf('const secondUrl =');
  assert.ok(segStart > 0, '未找到 secondUrl 的校验段（`const secondUrl =` 缺失）—— 校验逻辑可能已被删除');
  const seg = src.slice(segStart, segStart + 1200);
  assert.ok(/assertSafeHttpTarget\s*\(\s*secondUrl\s*\)/.test(seg), 'secondUrl 必须过 assertSafeHttpTarget');
  assert.ok(/assertInScope\s*\(\s*secondUrl\s*/.test(seg), 'secondUrl 必须过 assertInScope（授权范围）');
  assert.ok(/secondUrl\s*=\s*''/.test(seg), '校验不过时应清空 secondUrl（引擎按空串回退触发页），而不是带病放行');
});
