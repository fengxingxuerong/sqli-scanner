import { describe, it, expect, beforeEach } from 'vitest';
import { useScanStore } from '../store/scanStore';
import type { ReportModel } from '../shared/types';

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

  it('setScanId / setStatus / setReport 生效', () => {
    const { setScanId, setStatus, setReport } = useScanStore.getState();
    setScanId('abc');
    setStatus('running');
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

  it('setScanConcurrency 写入并发度快照', () => {
    const { setScanConcurrency } = useScanStore.getState();
    setScanConcurrency(5);
    expect(useScanStore.getState().scanConcurrency).toBe(5);
    setScanConcurrency(null);
    expect(useScanStore.getState().scanConcurrency).toBeNull();
  });

  it('reset 同时清空 scanConcurrency', () => {
    const { setScanConcurrency, reset } = useScanStore.getState();
    setScanConcurrency(8);
    reset();
    expect(useScanStore.getState().scanConcurrency).toBeNull();
  });
});
