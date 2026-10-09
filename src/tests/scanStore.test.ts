import { describe, it, expect, beforeEach } from 'vitest';
import { useScanStore } from '../store/scanStore';
import type { ReportModel, InjectionPoint } from '../shared/types';

// 与 SSE 协议同形的最小夹具（types.ts 的 ScanEventPayloads / InjectionPoint）——
// 本用例测的是"聚合与滑窗截断解耦"，用的入参仍必须是引擎真会发的那种事件，
// 否则将来 addEvent 改了取数路径（比如按 technique 计数）这条用例会静默失去意义。
const point = (id: string): InjectionPoint => ({
  id,
  location: 'url',
  param: 'id',
  originalValue: '1',
  confirmed: false,
  technique: null,
  dbms: null,
});

// 构造最小 ReportModel 快照（供 saveScanToHistory 使用）
function makeReport(scanId: string): ReportModel {
  return {
    scanId,
    target: { baseUrl: `http://t/${scanId}` } as ReportModel['target'],
    startedAt: '',
    finishedAt: '',
    dbms: null,
    points: [],
    vulns: [],
    data: null,
    riskLevel: 'Low',
    summary: {},
  };
}

describe('scanStore', () => {
  beforeEach(() => {
    // 清空会话态与历史（含持久化），避免跨测试污染
    useScanStore.setState({
      scanId: null,
      status: 'pending',
      report: null,
      events: [],
      history: [],
    });
    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        window.localStorage.removeItem('sqli_scan_history_v1');
      }
    } catch {
      /* 无 localStorage 环境忽略 */
    }
  });

  it('初始状态正确', () => {
    const s = useScanStore.getState();
    expect(s.scanId).toBeNull();
    expect(s.status).toBe('pending');
    expect(s.events).toEqual([]);
    expect(s.history).toEqual([]);
  });

  // H2：进度聚合增量维护 —— events 滑窗截断后聚合值仍存活，进度条不归零
  it('addEvent 增量维护进度聚合；滑窗截断早期事件后聚合不丢失', () => {
    // 先重置聚合（beforeEach 未覆盖新字段）
    useScanStore.setState({ events: [], progressTotal: 0, processedPointIds: {} });
    const { addEvent } = useScanStore.getState();
    addEvent({
      type: 'point_discovered', scanId: 's1', ts: '',
      payload: { points: [point('p1'), point('p2'), point('p3')] },
    });
    addEvent({ type: 'point_testing', scanId: 's1', ts: '', payload: { pointId: 'p1', technique: 'union' } });
    addEvent({
      type: 'detection_found', scanId: 's1', ts: '',
      payload: {
        pointId: 'p2', technique: 'union', vulnerable: true, dbms: 'MySQL',
        evidence: 'x', payloads: ['x'], riskLevel: 'High',
      },
    });
    // 重复 pointId 不重复计数
    addEvent({ type: 'point_skipped', scanId: 's1', ts: '', payload: { pointId: 'p2', reason: 'prefilter' } });

    let s = useScanStore.getState();
    expect(s.progressTotal).toBe(3);
    expect(Object.keys(s.processedPointIds).sort()).toEqual(['p1', 'p2']);

    // 灌满滑窗触发截断（>300 条），早期 point_discovered 被挤出
    for (let i = 0; i < 320; i++) {
      addEvent({
        type: 'http_request', scanId: 's1', ts: '',
        payload: { method: 'GET', url: `http://t/?i=${i}`, status: 200 },
      });
    }
    s = useScanStore.getState();
    expect(s.events.length).toBe(300);
    expect(s.events.some((e) => e.type === 'point_discovered')).toBe(false);
    // 聚合不受滑窗影响
    expect(s.progressTotal).toBe(3);
    expect(Object.keys(s.processedPointIds).length).toBe(2);

    // clearEvents 归零
    useScanStore.getState().clearEvents();
    s = useScanStore.getState();
    expect(s.progressTotal).toBe(0);
    expect(s.processedPointIds).toEqual({});
  });

  it('setScanId / setStatus / setReport 生效', () => {
    const { setScanId, setStatus, setReport } = useScanStore.getState();
    setScanId('abc');
    setStatus('running');
    // 这里**保留**一处主动绕过：setReport 只是把值存进 store，用例断言的也只是"存进去取得出"。
    // 造一份完整 ReportModel 会把这条用例变成 ReportModel 的形态测试（另一条用例的职责）。
    setReport({ scanId: 'abc' } as unknown as ReportModel);
    const s = useScanStore.getState();
    expect(s.scanId).toBe('abc');
    expect(s.status).toBe('running');
    expect(s.report?.scanId).toBe('abc');
  });

  it('addEvent 最多保留 300 条（防止内存膨胀）', () => {
    const { addEvent } = useScanStore.getState();
    for (let i = 0; i < 305; i++) addEvent({ type: 'p', ts: String(i), payload: null } as any);
    expect(useScanStore.getState().events.length).toBe(300);
  });

  it('saveScanToHistory 最多保留 100 条且最新置顶', () => {
    const { saveScanToHistory } = useScanStore.getState();
    for (let i = 0; i < 105; i++) saveScanToHistory(makeReport(String(i)));
    const h = useScanStore.getState().history;
    expect(h.length).toBe(100);
    expect(h[0].scanId).toBe('104');
  });

  it('saveScanToHistory 同 scanId 去重', () => {
    const { saveScanToHistory } = useScanStore.getState();
    saveScanToHistory(makeReport('dup'));
    saveScanToHistory(makeReport('dup'));
    const h = useScanStore.getState().history.filter((r) => r.scanId === 'dup');
    expect(h.length).toBe(1);
  });

  it('removeHistory 软删除单条', () => {
    const { saveScanToHistory, removeHistory } = useScanStore.getState();
    saveScanToHistory(makeReport('a'));
    saveScanToHistory(makeReport('b'));
    removeHistory('a');
    const h = useScanStore.getState().history;
    expect(h.find((r) => r.scanId === 'a')).toBeUndefined();
    expect(h.find((r) => r.scanId === 'b')).toBeDefined();
  });

  it('clearEvents 清空事件流', () => {
    const { addEvent, clearEvents } = useScanStore.getState();
    addEvent({ type: 'p', ts: '1', payload: null } as any);
    clearEvents();
    expect(useScanStore.getState().events).toEqual([]);
  });

  it('reset 清空会话态', () => {
    const { setScanId, reset } = useScanStore.getState();
    setScanId('x');
    reset();
    const s = useScanStore.getState();
    expect(s.scanId).toBeNull();
    expect(s.events).toEqual([]);
    expect(s.report).toBeNull();
  });
});
