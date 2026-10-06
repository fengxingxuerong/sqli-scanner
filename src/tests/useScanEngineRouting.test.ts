// @vitest-environment node
// ============================================================================
// src/tests/useScanEngineRouting.test.ts
// 「引擎 → 端点」判据的单一真源守卫
//
// ── 为什么必须有（2026-10-06 收敛）──────────────────────────────────────────
// useScan.ts 此前把同一判据**逐字抄了 4 遍**：
//     const engine = st.scanId === scanId && st.scanEngine ? st.scanEngine : st.engine;
//     const base = engine === 'sqlmap' ? '/sqlmap' : '/scan';
//   · engine 判定 3 处：stopScan / pauseScan / resumeScan
//   · base 判定 4 处：上述三处 + getReport
//
// 同一判据多份实现的后果在本项目有反复前科：改路由策略时漏改一处，而漏改的
// 表现是**「UI 显示成功、后端根本没收到那条请求」** —— 静默失败，最难查。
//
// 本轮收敛为 engineBase() / pickEngine() 两个导出函数。
// ⚠️ getReport 的 engine 判定是**三级优先级**（多一步 history 回溯），
//   本轮**刻意没有**合并进 pickEngine：合并会悄悄丢掉
//   「历史快照按记录内 report.engine 回溯」这条能力（sqlmap 历史记录回溯不再误发 /scan）。
//   这条差异由下面的「差异登记」一组钉住。
// ============================================================================

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { engineBase, pickEngine } from '../hooks/useScan';

const SRC = readFileSync(
  fileURLToPath(new URL('../hooks/useScan.ts', import.meta.url)), 'utf8',
).replace(/\r\n/g, '\n');

type Engine = 'builtin' | 'sqlmap';
interface St { scanId?: string | null; scanEngine?: Engine | null; engine: Engine }

describe('engineBase：引擎 → 端点前缀', () => {
  it('自证-0: 两种引擎映射到不同前缀（否则本组守卫前提失效）', () => {
    expect(engineBase('builtin')).toBe('/scan');
    expect(engineBase('sqlmap')).toBe('/sqlmap');
    expect(engineBase('builtin')).not.toBe(engineBase('sqlmap'));
  });

  it('两个引擎值都被覆盖（新增引擎时不得忘了加分支）', () => {
    const covered = new Set([engineBase('builtin'), engineBase('sqlmap')]);
    expect([...covered].sort()).toEqual(['/scan', '/sqlmap']);
  });
});

describe('pickEngine：会话快照优先于 UI 当前选择', () => {
  // 这条判据的存在理由：用户在扫描期间切换 UI 引擎时，stop/pause/resume
  // 必须仍然发给**启动时那套**后端，否则扫描停不下来。
  it('会话 id 匹配且有快照 → 用启动时的快照（无视 UI 当前选择）', () => {
    const st: St = { scanId: 's1', scanEngine: 'sqlmap', engine: 'builtin' };
    expect(pickEngine(st, 's1')).toBe('sqlmap');
  });

  it('会话 id 匹配但快照为 null → 回退 UI 选择', () => {
    const st: St = { scanId: 's1', scanEngine: null, engine: 'sqlmap' };
    expect(pickEngine(st, 's1')).toBe('sqlmap');
  });

  it('会话 id 不匹配（历史记录）→ 回退 UI 选择', () => {
    const st: St = { scanId: 's1', scanEngine: 'sqlmap', engine: 'builtin' };
    expect(pickEngine(st, 'other')).toBe('builtin');
  });

  it('store 里完全没有会话（scanId 为空）→ 回退 UI 选择', () => {
    const st: St = { scanId: null, scanEngine: null, engine: 'sqlmap' };
    expect(pickEngine(st, 'anything')).toBe('sqlmap');
  });

  it('端点前缀必须跟着引擎一起走（组合行为）', () => {
    expect(engineBase(pickEngine({ scanId: 's1', scanEngine: 'sqlmap', engine: 'builtin' }, 's1')))
      .toBe('/sqlmap');
    expect(engineBase(pickEngine({ scanId: 's1', scanEngine: 'builtin', engine: 'sqlmap' }, 's1')))
      .toBe('/scan');
  });
});

describe('差异登记：getReport 的三级判定不得被误合并', () => {
  // 收敛时最容易犯的错：把 getReport 也换成 pickEngine，
  // 结果「历史 sqlmap 记录回溯」又发回 /scan 路由（后端会话已回收 ⇒ 404）。
  // 判据直接从源码取，证明那三级分支还在。
  it('getReport 必须保留 history 回溯分支（用 rec.report.engine 而非 st.engine）', () => {
    const body = SRC.slice(SRC.indexOf('const getReport = useCallback'));
    expect(body).toContain('st.history.find((h) => h.scanId === scanId)');
    expect(body).toContain('rec?.report?.engine');
  });

  it('getReport 仍必须优先用当前会话快照（第①优先级）', () => {
    const body = SRC.slice(SRC.indexOf('const getReport = useCallback'));
    expect(body).toContain('st.scanId === scanId && st.scanEngine');
  });
});

describe('收敛：判据在文件里只能各有一份实现', () => {
  const body = SRC.slice(SRC.indexOf('export function useScan()'));

  it('三元 base 判定不得再出现在实现里（防新调用点手抄一份）', () => {
    const hits = body.match(/engine === 'sqlmap' \? '\/sqlmap' : '\/scan'/g) ?? [];
    expect(hits, `实现里仍有 ${hits.length} 处手抄的 base 判定，应改用 engineBase()`).toEqual([]);
  });

  it('引擎快照三元判定不得再出现在 stop/pause/resume 里（应改用 pickEngine）', () => {
    const hits = body.match(/st\.scanId === scanId && st\.scanEngine \? st\.scanEngine : st\.engine/g) ?? [];
    expect(hits, `实现里仍有 ${hits.length} 处手抄的引擎判定，应改用 pickEngine()`).toEqual([]);
  });

  it('自证-1: 判据本身在文件中确实存在（防守卫因改名而永远绿）', () => {
    // 守卫 ①② 若实现被整体重写成别的写法，上面两条会「因为找不到而绿」——
    // 这是假绿。这里证明判据仍以函数形式存在于本文件。
    expect(SRC).toContain('export function engineBase');
    expect(SRC).toContain('export function pickEngine');
    expect(SRC).toMatch(/return engine === 'sqlmap' \? '\/sqlmap' : '\/scan';/);
  });
});
