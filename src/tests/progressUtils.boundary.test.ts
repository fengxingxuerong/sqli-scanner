// ============================================================================
// src/tests/progressUtils.boundary.test.ts
// 阶段耗时与徽章计数的边界行为
//
// 取证动机：computeStageTimings 用 `[...events].reverse().find(...)` 取「末个」
// detection_found / extraction_progress，用 `events.find(...)` 取「首个」
// point_testing / extraction_progress。二者组合在**事件时序不单调**时会
// 算出负时长，被 secondsBetween 的 `Math.max(0, ·)` 归零 ⇒ 阶段整条消失。
//
// 本文件先把实测到的行为钉住（不是修，是确认），再决定哪些算缺陷。
// ============================================================================
import { describe, it, expect } from 'vitest';
import {
  secondsBetween, computeStageTimings, computeBadges, getEventStyle,
} from '../components/progress/progressUtils';
import type { ScanEvent } from '../shared/types';

const T0 = '2026-01-01T00:00:00.000Z';
const at = (sec: number) => new Date(Date.parse(T0) + sec * 1000).toISOString();
const ev = (type: string, sec: number): ScanEvent =>
  ({ type, ts: at(sec), payload: {} }) as unknown as ScanEvent;

describe('secondsBetween：边界取值', () => {
  it('自证-0: 正常递增算出真实秒差（否则本组前提失效）', () => {
    expect(secondsBetween(T0, at(10))).toBe(10);
    expect(secondsBetween(T0, at(90))).toBe(90);
    expect(secondsBetween(T0, at(0.5))).toBe(0.5);
  });

  it('时间倒退归零而不返回负数', () => {
    expect(secondsBetween(T0, at(-10))).toBe(0);
  });

  it('同一时刻归零', () => {
    expect(secondsBetween(T0, T0)).toBe(0);
  });

  it('任一端是非法日期字符串时归零（不得返回 NaN）', () => {
    expect(secondsBetween(T0, 'not-a-date')).toBe(0);
    expect(secondsBetween('not-a-date', T0)).toBe(0);
    expect(secondsBetween('x', 'y')).toBe(0);
  });

  it('空串 / undefined 不得抛错', () => {
    expect(() => secondsBetween('', '')).not.toThrow();
    expect(Number.isNaN(secondsBetween(T0, ''))).toBe(false);
  });
});

describe('computeStageTimings：事件时序不单调时的行为', () => {
  it('正常时序：探测 → 提取 → 总计三段齐全', () => {
    const events = [
      ev('scan_started', 0),
      ev('point_testing', 1),
      ev('detection_found', 5),
      ev('extraction_progress', 6),
      ev('extraction_progress', 10),
    ];
    const labels = computeStageTimings(events).map((s) => s.label);
    expect(labels).toEqual(['progress.stageDetect', 'progress.stageExtract', 'progress.stageTotal']);
    const detect = computeStageTimings(events).find((s) => s.label === 'progress.stageDetect');
    expect(detect?.seconds).toBe(4);
  });

  it('多个 detection_found 时必须取末个（注入③ 抓出守卫缺口后补的）', () => {
    // 初版守卫只放了一个 detection_found ⇒ 取首个与取末个结果相同，
    // 于是「把 lastDf 改成 events.find(...)」这个注入仍然全绿 —— 判据太弱。
    // 而**多命中恰恰是检测器的常态**，这才是真正该钉住的场景。
    const events = [
      ev('scan_started', 0),
      ev('point_testing', 1),
      ev('detection_found', 3),
      ev('detection_found', 7),
      ev('detection_found', 11),
    ];
    const detect = computeStageTimings(events).find((s) => s.label === 'progress.stageDetect');
    // 首个 testing@1s → 末个 found@11s = 10s；若误取首个 found@3s 则只有 2s
    expect(detect?.seconds, '探测阶段必须算到末个命中（10s），而不是首个命中（2s）').toBe(10);
  });

  it('多个 extraction_progress 时取首尾跨度（注入③ 同类）', () => {
    const events = [
      ev('scan_started', 0),
      ev('extraction_progress', 4),
      ev('extraction_progress', 9),
      ev('extraction_progress', 14),
    ];
    const extract = computeStageTimings(events).find((s) => s.label === 'progress.stageExtract');
    expect(extract?.seconds, '提取阶段必须是首尾跨度 10s').toBe(10);
  });

  it('检测早于测试时，探测阶段整条消失（实测记录，非断言期望）', () => {
    // detection_found@5s 早于首个 point_testing@10s ⇒ 负时长被 Math.max(0,·) 归零
    // ⇒ `d > 0` 不成立 ⇒ 该阶段不 push。
    const events = [ev('point_discovered', 0), ev('detection_found', 5), ev('point_testing', 10)];
    const labels = computeStageTimings(events).map((s) => s.label);
    expect(labels).not.toContain('progress.stageDetect');
    // 总计仍在（首尾都是合法时间）
    expect(labels).toContain('progress.stageTotal');
  });

  it('空数组 / 单条事件返回空阶段列表（不得抛错）', () => {
    expect(computeStageTimings([])).toEqual([]);
    expect(computeStageTimings([ev('scan_started', 0)])).toEqual([]);
  });

  it('脏事件（ts 缺失或非法）不得抛错，总计不得为 NaN', () => {
    const events = [
      ev('scan_started', 0),
      { type: 'point_testing' } as unknown as ScanEvent,
      { type: 'detection_found', ts: 'bad' } as unknown as ScanEvent,
    ];
    let out;
    expect(() => { out = computeStageTimings(events); }).not.toThrow();
    for (const s of out!) {
      expect(Number.isNaN(s.seconds), `${s.label} 的 seconds 为 NaN`).toBe(false);
    }
  });

  it('只有一条 extraction_progress 时不产出提取阶段（时长为 0 被 d>0 滤掉）', () => {
    const events = [ev('scan_started', 0), ev('extraction_progress', 3)];
    expect(computeStageTimings(events).map((s) => s.label)).not.toContain('progress.stageExtract');
  });
});

describe('computeBadges：计数口径', () => {
  it('只输出计数大于 0 的徽章', () => {
    const out = computeBadges([ev('point_discovered', 0)]);
    expect(out.map((b) => b.label)).toEqual(['progress.badgeDiscovered']);
    expect(computeBadges([])).toEqual([]);
  });

  it('命中数合并内置引擎 detection_found 与 sqlmap_vuln 两条来源', () => {
    const out = computeBadges([
      ev('detection_found', 0), ev('detection_found', 1), ev('sqlmap_vuln', 2),
    ]);
    const hits = out.find((b) => b.label === 'progress.badgeHits');
    expect(hits?.count).toBe(3);
  });

  it('已测点按 point_testing 计数，不得把 point_discovered 也算进去', () => {
    const out = computeBadges([
      ev('point_discovered', 0), ev('point_discovered', 1), ev('point_testing', 2),
    ]);
    expect(out.find((b) => b.label === 'progress.badgeDiscovered')?.count).toBe(2);
    expect(out.find((b) => b.label === 'progress.badgeTested')?.count).toBe(1);
  });
});

describe('getEventStyle：未知类型回落', () => {
  it('未知事件类型必须回落到默认样式而不得抛错', () => {
    expect(getEventStyle('totally_unknown_event')).toBeTruthy();
    expect(getEventStyle('')).toBeTruthy();
  });

  it('已知事件类型有非灰色样式（防止新增事件忘了登记）', () => {
    // 白名单式登记：时间线上真正用到的终态/进度事件必须显式有样式
    for (const t of ['scan_started', 'scan_completed', 'scan_error', 'point_discovered',
      'point_testing', 'detection_found', 'extraction_progress', 'sqlmap_vuln']) {
      expect(getEventStyle(t).color, `${t} 走了灰色默认`).not.toBe('#757575');
    }
  });
});
