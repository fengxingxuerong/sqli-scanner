// ============================================================================
// historyMerge 单测 —— History 页「服务端 ∪ 本地」合并规则
// ============================================================================
// 为什么单独测这一层：组件测试要么被网络 mock 复杂化，要么像 qa_history 那样只碰到
// 降级路径（服务端拿不到时退回本地）就把用例跑绿了 —— **合流规则本身没人验证**。
// 纯函数放在这里打，能用最小的成本挡住最容易犯的错（兜底成 'Low'、丢本地快照、乱排序）。
// ============================================================================
import { describe, it, expect } from 'vitest';
import { mergeHistory } from '../shared/historyMerge';
import type { HistoryRecord, ReportModel } from '../shared/types';

function serverRow(over: Record<string, unknown> = {}) {
  return {
    scanId: 's1',
    target: 'http://server-target',
    method: 'GET',
    startedAt: null,
    finishedAt: '2026-09-29T00:00:00.000Z',
    points: 1,
    vulns: 3,
    riskLevel: 'High',
    dbms: 'MySQL',
    verdict: 'vulnerability_detected',
    source: 'ledger' as const,
    ...over,
  };
}

function localRow(scanId: string, over: Partial<HistoryRecord> = {}): HistoryRecord {
  const report = {
    scanId,
    target: { baseUrl: `http://local-${scanId}`, config: { sessionFile: 'f.json' } },
    vulns: [{ id: 'v1' }],
    engine: 'builtin',
  } as unknown as ReportModel;
  return {
    schemaVersion: 1,
    scanId,
    target: `http://local-${scanId}`,
    riskLevel: 'Low',
    finishedAt: '2026-09-29T00:00:00.000Z',
    report,
    ...over,
  };
}

describe('mergeHistory', () => {
  it('同一 scanId：服务端行胜出做展示，但必须保住本地快照（续跑要用它）', () => {
    const rows = mergeHistory([serverRow({ scanId: 'same' })], [localRow('same')]);
    expect(rows.length).toBe(1);
    expect(rows[0].target).toBe('http://server-target', '展示用服务端那条（跨设备一致）');
    expect(rows[0].vulns).toBe(3, '漏洞数取自服务端摘要');
    expect(rows[0].local?.scanId).toBe('same', '本地快照必须留着，否则续跑配置无处可取');
    expect(rows[0].source).toBe('ledger');
  });

  it('本地独有的条目要追加进来并标 local（不能因为接了服务端就看不见了）', () => {
    const rows = mergeHistory([serverRow({ scanId: 'srv' })], [localRow('only-local')]);
    expect(rows.map((r) => r.scanId).sort()).toEqual(['only-local', 'srv']);
    const local = rows.find((r) => r.scanId === 'only-local');
    expect(local?.source).toBe('local');
  });

  it('riskLevel：服务端优先；服务端没有才看本地', () => {
    expect(mergeHistory([serverRow({ riskLevel: 'Critical' })], [localRow('s1', { riskLevel: 'Low' })])[0].riskLevel)
      .toBe('Critical');
    // 老台账没固化 highestRisk ⇒ null，此时退回本地快照的值
    expect(mergeHistory([serverRow({ riskLevel: null })], [localRow('s1', { riskLevel: 'Medium' })])[0].riskLevel)
      .toBe('Medium');
  });

  it('风险等级不得兜底成 Low（没有就是 null，污染 UI 色标）', () => {
    // 服务端脏值 + 本地也没有 ⇒ null，而不是悄悄塞一个 Low
    expect(mergeHistory([serverRow({ riskLevel: 'weird' })], [])[0].riskLevel).toBe(null);
    expect(mergeHistory([serverRow({ riskLevel: null })], [])[0].riskLevel).toBe(null);
    expect(mergeHistory([serverRow({ riskLevel: 'Low' })], [])[0].riskLevel).toBe('Low', '规范值要照常透传');
  });

  it('按时间降序排序；缺时间的排最后（不假装它是最新的）', () => {
    const rows = mergeHistory(
      [
        serverRow({ scanId: 'old', finishedAt: '2026-01-01T00:00:00.000Z' }),
        serverRow({ scanId: 'no-time', finishedAt: null, startedAt: null }),
        serverRow({ scanId: 'new', finishedAt: '2026-12-01T00:00:00.000Z' }),
      ],
      []
    );
    expect(rows.map((r) => r.scanId)).toEqual(['new', 'old', 'no-time']);
  });

  it('source=live 的条目如实标记为 live', () => {
    expect(mergeHistory([serverRow({ source: 'live' })], [])[0].source).toBe('live');
  });

  it('脏输入不崩：null / undefined / 缺 scanId 的行被跳过', () => {
    expect(() => mergeHistory(undefined, undefined)).not.toThrow();
    expect(mergeHistory([], []).length).toBe(0);
    const rows = mergeHistory(
      [serverRow({ scanId: '' }), serverRow({ scanId: 'ok' })],
      [localRow('')]
    );
    expect(rows.map((r) => r.scanId)).toEqual(['ok']);
  });
});
