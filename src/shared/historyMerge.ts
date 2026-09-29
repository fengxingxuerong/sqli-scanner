// ============================================================================
// historyMerge.ts —— 服务端清单（GET /api/scans）与浏览器本地历史的合并规则
// ============================================================================
// 为什么要有这一层：
//   History 页此前只读 localStorage ⇒ 换台机器、换个浏览器、清一次缓存，历史就没了。
//   服务端台账早就存在（CLI 一直在写），只是 Web 侧没接。但**本地不能直接删** ——
//   本地那份带完整 report 快照，是"离线回溯"和"续跑"的唯一来源；服务端行只有摘要。
//
// 合并规则（三条，按重要性排序）：
//   ① 同一 scanId：服务端行胜出做展示（它是跨设备事实源），但**保留本地引用** ——
//      续跑要读 report.target.config，只有本地那份有。
//   ② 只有本地有的条目：追加进来，标 source='local'。这些通常发生在服务端未开、
//      或服务端台账被保留策略淘汰之后，丢掉白丢。
//   ③ 排序按时间降序；时间缺失的排最后（不假装它是最新的）。
// ============================================================================
import type { HistoryRecord, RiskLevel } from './types';
import type { ServerScanRow } from './apiClient';

export interface MergedHistoryRow {
  scanId: string;
  target: string;
  finishedAt: string | null;
  riskLevel: RiskLevel | null;
  vulns: number;
  /** 本地快照（服务端没有 report 全文；有它才能续跑） */
  local?: HistoryRecord;
  /** 数据来源：ledger=服务端台账 · live=服务端在途 · local=仅本地 */
  source: 'ledger' | 'live' | 'local';
}

const isRisk = (v: unknown): v is RiskLevel =>
  v === 'Critical' || v === 'High' || v === 'Medium' || v === 'Low';

/** 时间键：取不到时间的记 ''（localeCompare 会把它排到升序最前 ⇒ 反转后落最后） */
function timeKey(row: { finishedAt?: string | null; startedAt?: string | null }): string {
  return String(row.finishedAt ?? row.startedAt ?? '');
}

/**
 * 合并服务端清单与本地历史。纯函数，不触网络、不读 store —— 便于直接单测。
 * @param serverRows GET /api/scans 的 data.scans（可能为空数组）
 * @param localRows  本地 zustand 持久化的历史
 */
export function mergeHistory(
  serverRows: readonly ServerScanRow[] = [],
  localRows: readonly HistoryRecord[] = []
): MergedHistoryRow[] {
  const out: MergedHistoryRow[] = [];
  const localById = new Map<string, HistoryRecord>();
  for (const h of localRows) {
    if (h && h.scanId) localById.set(h.scanId, h);
  }
  const seen = new Set<string>();

  for (const s of serverRows || []) {
    if (!s || !s.scanId) continue;
    seen.add(s.scanId);
    const local = localById.get(s.scanId);
    out.push({
      scanId: s.scanId,
      target: s.target || local?.target || '',
      finishedAt: s.finishedAt ?? s.startedAt ?? local?.finishedAt ?? null,
      // 服务端先发言；服务端没存（老台账）就退回本地快照的值 —— 两条事实源挑有信息的那条，
      // **都不许兜底成 'Low'**：编出来的风险等级会污染 list/readme 之外的第二个地方。
      riskLevel: isRisk(s.riskLevel) ? s.riskLevel : (isRisk(local?.riskLevel) ? local!.riskLevel : null),
      vulns: typeof s.vulns === 'number' ? s.vulns : (local?.report?.vulns?.length ?? 0),
      local,
      source: s.source === 'live' ? 'live' : 'ledger',
    });
  }

  for (const h of localRows) {
    if (!h || !h.scanId || seen.has(h.scanId)) continue;
    out.push({
      scanId: h.scanId,
      target: h.target || h.report?.target?.baseUrl || '',
      finishedAt: h.finishedAt ?? null,
      riskLevel: isRisk(h.riskLevel) ? h.riskLevel : null,
      vulns: h.report?.vulns?.length ?? 0,
      local: h,
      source: 'local',
    });
  }

  return out.sort((a, b) => timeKey(b).localeCompare(timeKey(a)));
}
