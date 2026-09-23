// @vitest-environment node
// ============================================================================
// src/tests/requestParser.serverParity.test.ts —— 前端/服务端「请求行首行」文法契约
//
// 为什么必须有（2026-09-23）：请求解析在本项目有**两条独立实现**
//   · 服务端权威：`server/src/core/requestFileParser.js:25`（-r 导入、CLI 也走它）
//   · 前端：`src/shared/requestParser.ts`（UI「请求文件导入」按钮）
// 二者此前在「HTTP 版本是否必填」上不一致：前端必填、服务端可选 →
// 从 Burp 粘贴的**无版本**报文在 UI 上判非法、引擎却扫得了。同一份文本两端结论不同。
//
// 本测试不抄录服务端的值，而是**从服务端源码里抽**：任一侧改动，此处立刻红。
//
// 判据分三层：
//   ① 行为：无版本/带版本请求行都必须能解析（这是用户真正会撞到的形态）；
//   ② 结构：前端的两套方法集必须都是服务端方法集的**子集**（前端不得认服务端不认的方法，
//      否则会出现「UI 导入成功、引擎拒绝」这种反向断链）；
//   ③ 白名单：已知差异（服务端多 TRACE/CONNECT；PARSER 比 DETECT 多 HEAD/OPTIONS）
//      必须显式登记 —— 差异本身允许存在，但**变了就要让人看见**。
// ============================================================================

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  parseRequestFile,
  tryAutoDetect,
  looksLikeRawRequest,
  REQUEST_LINE_METHODS_PARSER,
  REQUEST_LINE_METHODS_DETECT,
} from '../shared/requestParser';

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

/** 从服务端源码里抽出请求行首行正则的方法集与「版本是否可选」 */
function serverRequestLine(): { methods: string[]; versionOptional: boolean } {
  const src = read('../../server/src/core/requestFileParser.js');
  const line = src.split('\n').find((l) => l.includes('GET|POST') && l.includes('HTTP'));
  if (!line) throw new Error('服务端 requestFileParser.js 里找不到请求行正则——改名了，本测试需同步');
  const mm = /\((GET\|[A-Z|]+)\)/.exec(line);
  if (!mm) throw new Error('服务端请求行正则里抽不出方法集');
  return {
    methods: mm[1].split('|'),
    // `(?:\s+HTTP\/[\d.]+)?` 末尾的 `?` = 版本可选
    versionOptional: /HTTP\\\/\[\\d\.\]\+\)\s*\?/.test(line),
  };
}

// ③ 已知差异白名单
const KNOWN_SERVER_ONLY_METHODS = ['TRACE', 'CONNECT']; // 服务端支持、前端有意不支持
const KNOWN_PARSER_ONLY_METHODS = ['HEAD', 'OPTIONS']; // PARSER 能认首行、DETECT 因 MethodType 限制不认

describe('请求行首行：前端 ↔ 服务端契约', () => {
  const SERVER = serverRequestLine();

  // ① 行为：这是用户真正会撞到的形态
  it('①a 带 HTTP 版本的请求行可解析（既有行为不得回退）', () => {
    const raw = 'POST /api/x HTTP/1.1\r\nHost: h.com\r\n\r\nuser=admin';
    const r = parseRequestFile(raw);
    expect(r).not.toBeNull();
    expect(r!.method).toBe('POST');
    expect(r!.url).toContain('h.com');
  });

  it('①b 无 HTTP 版本的请求行可解析（Burp 粘贴形态；此前 UI 判非法、引擎能扫）', () => {
    const raw = 'GET /items?cat=1\r\nHost: h.com\r\n';
    const r = parseRequestFile(raw);
    expect(r).not.toBeNull();
    expect(r!.method).toBe('GET');
    expect(r!.url).toBe('http://h.com/items?cat=1');
    // 注入候选必须拿到，否则导入无意义
    expect(r!.params).toEqual({ cat: '1' });
  });

  it('①c 自动识别（tryAutoDetect / looksLikeRawRequest）同样接受无版本', () => {
    expect(looksLikeRawRequest('GET /a\r\nHost: h.com\r\n')).toBe(true);
    expect(tryAutoDetect('GET /items?id=2\r\nHost: h.com\r\n')).toMatchObject({
      url: 'http://h.com/items?id=2',
      method: 'GET',
    });
  });

  it('①d 无 Host 头仍返回 null（放宽版本不应把缺 Host 的片段误判为请求）', () => {
    expect(parseRequestFile('GET /a')).toBeNull();
    expect(tryAutoDetect('GET /a')).toBeNull();
  });

  // ② 结构：前端不得认服务端不认的方法
  it('② PARSER 方法集必须是服务端方法集的子集', () => {
    const outside = REQUEST_LINE_METHODS_PARSER.filter((m) => !SERVER.methods.includes(m));
    expect(outside, `前端认了服务端不认的方法（会导致 UI 导入成功、引擎拒绝）：${outside.join(', ')}`).toEqual([]);
  });

  it('② DETECT 方法集必须是 PARSER 的子集（且受 MethodType 约束）', () => {
    const outside = REQUEST_LINE_METHODS_DETECT.filter(
      (m) => !(REQUEST_LINE_METHODS_PARSER as readonly string[]).includes(m)
    );
    expect(outside, `DETECT 认了 PARSER 不认的方法：${outside.join(', ')}`).toEqual([]);
  });

  it('② 版本可选性必须与服务端一致（这是本次修的断链）', () => {
    expect(SERVER.versionOptional, '服务端请求行已改为版本可选，前端需同步').toBe(true);
    // 前端侧的行为证据：无版本的请求行也要被判为「像原始请求」。
    // （若此处为 false，说明前端又把版本改回必填 → ①b 那类 Burp 粘贴会重新断链。）
    expect(looksLikeRawRequest('PUT /a')).toBe(true);
  });

  // ③ 白名单：差异必须显式登记，变了要让人看见
  it('③ 服务端多出的方法必须恰好等于白名单（防服务端悄悄加方法而 UI 不知）', () => {
    const serverOnly = SERVER.methods.filter(
      (m) => !(REQUEST_LINE_METHODS_PARSER as readonly string[]).includes(m)
    );
    expect(serverOnly.sort()).toEqual([...KNOWN_SERVER_ONLY_METHODS].sort());
  });

  it('③ PARSER 比 DETECT 多出的方法必须恰好等于白名单（防 MethodType 与首行正则脱钩）', () => {
    const parserOnly = REQUEST_LINE_METHODS_PARSER.filter(
      (m) => !(REQUEST_LINE_METHODS_DETECT as readonly string[]).includes(m)
    );
    expect(parserOnly.sort()).toEqual([...KNOWN_PARSER_ONLY_METHODS].sort());
  });

  it('判据有效性：服务端抽取必须拿到方法集（防源码改名导致断言空转）', () => {
    expect(SERVER.methods.length).toBeGreaterThanOrEqual(7);
    expect(SERVER.methods).toContain('GET');
    expect(SERVER.methods).toContain('HEAD');
  });
});
