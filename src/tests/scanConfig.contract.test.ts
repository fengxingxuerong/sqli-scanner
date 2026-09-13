// @vitest-environment node
// ============================================================================
// src/tests/scanConfig.contract.test.ts —— 面板键 → 请求体 config 的契约
// [P0-FIX 2026-09-09]
//
// 为什么必须有：后端只认 KNOWN_CFG_KEYS，**白名单外的键被 logger.debug 静默丢弃**——既不报错也不生效。
// 于是「面板上有个开关、引擎里也实现了、中间没接」这个缺陷在本项目连续出现了三批
// （delay/reqRate/maxReq → prefilterSinglePoint/testFilter/useRegistry/freshQueries/dbms → matchString 类型）。
// 每一次都靠人记住「新开关要接进请求体」；人记不住，所以让 CI 记住。
//
// 三条断言：
//   ① 面板里能改的每个键，都必须在 SCAN_CONFIG_KEYS 登记（否则它根本不会进 body）；
//   ② SCAN_CONFIG_KEYS 的每个键，后端 KNOWN_CFG_KEYS 必须认（否则前端发了也被丢）；
//   ③ 值类型必须与后端解析口径一致（matchString 是字符串，不是布尔——布尔会让引擎按「页面含 'true'」判定）。
// ============================================================================

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { SCAN_CONFIG_KEYS, SCAN_CONFIG_VALUE_TYPES, DEFAULT_CONFIG } from '../shared/constants';
import { buildStartConfig, buildResumeConfig } from '../shared/scanConfig';

// [audit-FIX 2026-09-13] 本套件只读源码文本，不需要 DOM。原默认 jsdom 环境下
// node:url/node:path 的函数导出在本机 Node 24 上被覆盖为 undefined（fileURLToPath/
// resolve is not a function，套件直接挂起）。声明 @vitest-environment node 后恢复
// 原生实现，路径逻辑零改动。
const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

/**
 * 后端 REST 白名单：直接从 server/src/api/scanRoutes.js 源码里把 KNOWN_CFG_KEYS 抓出来。
 * 为什么抽而不拄：拄录早晚会与后端漂移（本测试要防的就是漂移）；抽源码后，后端加键忘接线
 * 会直接在前端测试里抱，而不需要两边手动同步。
 * 用源码级提取而不是 import：前端测试不该依赖后端模块图（依赖环境/环境变量）。
 */
function backendKnownCfgKeys(): string[] {
  const src = read('../../server/src/api/scanRoutes.js');
  const start = src.indexOf('KNOWN_CFG_KEYS');
  if (start < 0) throw new Error('未在 scanRoutes.js 里找到 KNOWN_CFG_KEYS——后端改名了，本测试需同步');
  // 注意：它是 `new Set([...])`，所以边界是 `]);` 而不是第一个 `]`（否则只能抽到首行几个键）
  const end = src.indexOf(']);', start);
  const seg = src.slice(start, end);
  return [...seg.matchAll(/'([a-zA-Z0-9_]+)'/g)].map((m) => m[1]);
}

describe('配置契约：面板 → 请求体 → 后端白名单', () => {
  const panelSrc = read('../components/ScanConfigPanel.tsx');
  const BACKEND_KNOWN_CFG_KEYS = backendKnownCfgKeys();

  /** 面板实际会写的键：handle*('k') 与 store 直写 set('k', …) 两类写法 */
  const panelKeys = (() => {
    const found = new Set<string>();
    const patterns = [
      /handle[A-Za-z]*\(\s*'([a-zA-Z]+)'/g,
      /(?:setConfig|updateConfig|patchConfig)\(\s*'([a-zA-Z]+)'/g,
      /\bset\(\s*'([a-zA-Z]+)'/g,
    ];
    for (const re of patterns) {
      for (const m of panelSrc.matchAll(re)) found.add(m[1]);
    }
    return [...found];
  })();

  it('面板确实被扫到了键（防止正则失效导致本测试静默空转）', () => {
    expect(panelKeys.length).toBeGreaterThan(10);
  });

  it('① 面板里能改的每个键都在 SCAN_CONFIG_KEYS 登记', () => {
    const missing = panelKeys.filter((k) => !(SCAN_CONFIG_KEYS as readonly string[]).includes(k));
    expect(missing, `这些面板键不会进请求体：${missing.join(', ')}`).toEqual([]);
  });

  it('② SCAN_CONFIG_KEYS 每个键都被后端白名单接受', () => {
    const unknown = SCAN_CONFIG_KEYS.filter((k) => !BACKEND_KNOWN_CFG_KEYS.includes(k));
    expect(unknown, `后端会静默丢弃这些键：${unknown.join(', ')}`).toEqual([]);
  });

  it('③ 每个键都声明了值类型，且面板默认值类型与声明一致', () => {
    const types = SCAN_CONFIG_VALUE_TYPES as Record<string, string>;
    for (const key of SCAN_CONFIG_KEYS) {
      expect(types[key], `键 ${key} 缺少 SCAN_CONFIG_VALUE_TYPES 声明`).toBeTruthy();
    }
    // matchString/notString 必须是字符串语义：历史上被当布尔用过，引擎于是按「页面含 'true'」判真假
    expect(types.matchString).toBe('string');
    expect(types.notString).toBe('string');
    expect(typeof (DEFAULT_CONFIG as Record<string, unknown>).matchString !== 'boolean').toBe(true);
  });

  it('buildStartConfig：DEFAULT_CONFIG 里已定义的登记键全部出现在请求体', () => {
    const body = buildStartConfig(DEFAULT_CONFIG as never);
    const lost = SCAN_CONFIG_KEYS.filter(
      (k) => (DEFAULT_CONFIG as Record<string, unknown>)[k] !== undefined && body[k] === undefined
    );
    expect(lost, `这些键在默认配置下有值却没进请求体：${lost.join(', ')}`).toEqual([]);
  });

  it('buildStartConfig：前端未建模的键原样透传（历史回显/CLI 配置不被吃掉）', () => {
    const body = buildStartConfig({ delay: 3, reqRate: 5, blindRobust: true } as never);
    expect(body.delay).toBe(3);
    expect(body.reqRate).toBe(5);
    expect(body.blindRobust).toBe(true);
  });

  it('buildStartConfig：布尔的 false 必须照发，空串必须省略', () => {
    const body = buildStartConfig({ prefilter: false, matchString: '   ', retry: 0 } as never);
    expect(body.prefilter).toBe(false, '「关掉预筛」是一个动作，false 不发就等于没发');
    expect('matchString' in body).toBe(false, '空串锚点应省略（后端 clampStr 同义），否则会污染判定');
    expect(body.retry).toBe(0, '0 是合法值，不能被当成未配置丢掉');
  });

  it('buildResumeConfig：续跑必须带上 scope（授权范围不能在最常见路径上被丢掉）', () => {
    const saved = {
      scope: ['app.example.com'],
      delay: 2,
      sessionDefault: true,
      concurrency: 8,
    } as never;
    const cfg = buildResumeConfig(saved);
    expect(cfg.scope).toEqual(['app.example.com']);
    expect(cfg.delay).toBe(2, '续跑丢限速 = 第二轮比第一轮更凶');
    expect(cfg.sessionFile).toBe('sqli-session-latest.json');
    // 快照里没有 scope 时不得凭空造一个「看起来受限制」的值
    expect('scope' in buildResumeConfig({ concurrency: 4 } as never)).toBe(false);
  });

  it('后端白名单提取有效（含安全关键键；防提取失效导致断言空转）', () => {
    expect(BACKEND_KNOWN_CFG_KEYS.length).toBeGreaterThan(40);
    for (const k of ['scope', 'delay', 'reqRate', 'maxReq', 'confirmDestructive', 'productionMode', 'insecureTls', 'freshQueries']) {
      expect(BACKEND_KNOWN_CFG_KEYS, `后端白名单缺 ${k}`).toContain(k);
    }
  });
});
