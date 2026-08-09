// QA 独立验证（严过关）：F-17 历史记录持久化。
// 覆盖：saveScanToHistory 去重/置顶/截断100、removeHistory 软删除、
// localStorage 容错（损坏 JSON 不崩）、useEvents(scan_completed) 自动落库、
// 以及 HistoryPage UI 列出/回溯/删除。
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { renderHook } from '@testing-library/react';
import HistoryPage from '../pages/HistoryPage';
import { useScanStore } from '../store/scanStore';
import { useEvents } from '../hooks/useEvents';
import type { ReportModel } from '../shared/types';

function makeReport(scanId: string, target = `http://${scanId}`): ReportModel {
  return {
    scanId,
    target: { baseUrl: target } as ReportModel['target'],
    startedAt: '',
    finishedAt: '',
    dbms: null,
    points: [],
    vulns: [],
    data: null,
    riskLevel: 'Low',
    summary: {},
  } as ReportModel;
}

const HISTORY_KEY = 'sqli_scan_history_v1';

beforeEach(() => {
  localStorage.removeItem(HISTORY_KEY);
  useScanStore.setState({ history: [], report: null, status: 'pending' });
});

// ===== 纯 store 逻辑（独立重测去重/置顶/截断）=====
describe('F-17 saveScanToHistory', () => {
  it('去重 + 置顶 + 截断至 100', () => {
    const { saveScanToHistory } = useScanStore.getState();
    for (let i = 0; i < 105; i++) saveScanToHistory(makeReport(String(i)));
    const h = useScanStore.getState().history;
    expect(h.length).toBe(100);
    expect(h[0].scanId).toBe('104'); // 最新置顶
    // 再次保存已存在的 104 → 仍唯一且置顶
    saveScanToHistory(makeReport('104'));
    const after = useScanStore.getState().history;
    expect(after[0].scanId).toBe('104');
    expect(after.filter((r) => r.scanId === '104').length).toBe(1);
  });

  it('removeHistory 软删除单条（仅从数组过滤并回写）', () => {
    const { saveScanToHistory, removeHistory } = useScanStore.getState();
    saveScanToHistory(makeReport('a'));
    saveScanToHistory(makeReport('b'));
    removeHistory('a');
    const h = useScanStore.getState().history;
    expect(h.find((r) => r.scanId === 'a')).toBeUndefined();
    expect(h.find((r) => r.scanId === 'b')).toBeDefined();
  });
});

// ===== localStorage 容错 =====
describe('F-17 localStorage 容错', () => {
  it('损坏 JSON 不崩溃，回退空数组', async () => {
    localStorage.setItem(HISTORY_KEY, '{ this is not valid json');
    vi.resetModules();
    const mod = await import('../store/scanStore');
    expect(mod.useScanStore.getState().history).toEqual([]);
  });

  it('setItem 抛错时 saveScanToHistory 不崩溃，内存态仍更新', () => {
    const original = window.localStorage.setItem;
    window.localStorage.setItem = () => {
      throw new Error('quota exceeded');
    };
    expect(() => useScanStore.getState().saveScanToHistory(makeReport('z'))).not.toThrow();
    window.localStorage.setItem = original;
    expect(useScanStore.getState().history.find((r) => r.scanId === 'z')).toBeDefined();
  });
});

// ===== F-17 端到端：useEvents 收到 scan_completed 自动落库 =====
describe('F-17 useEvents 触发落库', () => {
  class FakeEventSource {
    static last: any = null;
    onmessage: ((ev: any) => void) | null = null;
    onerror: (() => void) | null = null;
    url: string;
    constructor(url: string) {
      this.url = url;
      FakeEventSource.last = this;
    }
    close() {}
  }

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('收到 scan_completed 事件 → saveScanToHistory + status=completed', () => {
    vi.stubGlobal('EventSource', FakeEventSource as any);
    useScanStore.setState({ history: [], status: 'pending', report: null });
    renderHook(() => useEvents('s1'));

    const report = makeReport('s1', 'http://s1');
    act(() => {
      FakeEventSource.last.onmessage({
        data: JSON.stringify({ type: 'scan_completed', scanId: 's1', ts: String(Date.now()), payload: report }),
      });
    });

    const h = useScanStore.getState().history;
    expect(h.find((r) => r.scanId === 's1')).toBeDefined();
    expect(useScanStore.getState().status).toBe('completed');
    expect(useScanStore.getState().report?.scanId).toBe('s1');
  });
});

// ===== HistoryPage UI：列出 / 回溯 / 删除 =====
describe('F-17 HistoryPage UI', () => {
  it('空历史显示占位文案', () => {
    render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    expect(screen.getByText('暂无历史记录')).toBeTruthy();
  });

  it('渲染历史列表，点击可回溯（setReport），删除按钮软删除', () => {
    useScanStore.setState({
      history: [
        { schemaVersion: 1, scanId: 'a', target: 'http://a', riskLevel: 'Low', finishedAt: null, report: makeReport('a') },
        { schemaVersion: 1, scanId: 'b', target: 'http://b', riskLevel: 'Low', finishedAt: null, report: makeReport('b') },
      ],
    });
    render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    expect(screen.getByText('http://a')).toBeTruthy();
    expect(screen.getByText('http://b')).toBeTruthy();

    // 回溯：点击列表项 → setReport 写入完整报告快照
    fireEvent.click(screen.getByText('http://a'));
    expect(useScanStore.getState().report?.scanId).toBe('a');

    // 删除 a（两条记录各有删除按钮，取第一条）
    const delButtons = screen.getAllByLabelText('删除');
    fireEvent.click(delButtons[0]);
    const h = useScanStore.getState().history;
    expect(h.find((r) => r.scanId === 'a')).toBeUndefined();
    expect(h.find((r) => r.scanId === 'b')).toBeDefined();
  });
});
