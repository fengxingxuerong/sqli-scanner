import { create } from 'zustand';
import type { ReportModel, ScanEvent, ScanStatus, HistoryRecord, EngineType, WafDetectedPayload, InjectionPoint } from '../shared/types';

// 历史记录持久化 key（schemaVersion=1，便于后续升级）
const HISTORY_KEY = 'sqli_scan_history_v1';
const HISTORY_LIMIT = 100;

// 从 localStorage 读取历史（容错：解析失败/不支持时回退空数组）
function loadHistory(): HistoryRecord[] {
  try {
    if (typeof window === 'undefined' || !window.localStorage) return [];
    const raw = window.localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    // 兼容旧结构（仅有 {scanId,target,riskLevel}，无 report）：保留用于展示/删除
    return parsed as HistoryRecord[];
  } catch {
    return [];
  }
}

// 写入 localStorage（容错：不可用时静默忽略）
function persistHistory(list: HistoryRecord[]): void {
  try {
    if (typeof window === 'undefined' || !window.localStorage) return;
    window.localStorage.setItem(HISTORY_KEY, JSON.stringify(list));
  } catch {
    /* 存储不可用（如隐私模式）时忽略 */
  }
}

// 扫描会话状态（zustand 单一数据源）
interface ScanState {
  scanId: string | null;
  status: ScanStatus;
  engine: EngineType;
  report: ReportModel | null;
  events: ScanEvent[];
  history: HistoryRecord[];
  // WAF 识别建议（waf_detected 事件载荷；仅推荐，不自动套用）
  wafSuggestion: WafDetectedPayload | null;
  // 二阶触发页自动发现（second_order_discovery 事件实时载荷；仅展示，不阻断）
  secondOrderDiscovery: {
    candidates: string[];
    confirmed: string[];
    storePoints?: { param: string; storeKind?: string | null }[];
  } | null;
  // 解析目标后实时发现的全部注入点（point_discovered 事件载荷；供扫描页实时全局拓扑）
  discoveredPoints: InjectionPoint[];
  // 当前扫描目标 URL（scan_started 事件载荷 target.baseUrl；供实时全局拓扑根节点）
  targetUrl: string | null;
  // 已确认漏洞的注入点 id 集合（detection_found 事件实时累积；供实时拓扑红框高亮）
  confirmedVulnPointIds: string[];
  // 本次扫描并发度（builtin: config.concurrency；sqlmap: sqlmapConfig.threads；仅展示用，不持久）
  scanConcurrency: number | null;
  setScanConcurrency: (n: number | null) => void;
  setScanId: (id: string) => void;
  setEngine: (e: EngineType) => void;
  setStatus: (s: ScanStatus) => void;
  setReport: (r: ReportModel) => void;
  addEvent: (e: ScanEvent) => void;
  clearEvents: () => void;
  // WAF 建议：写入 / 清空（新扫描开始时清空，避免残留上一次建议）
  setWafSuggestion: (s: WafDetectedPayload | null) => void;
  clearWafSuggestion: () => void;
  // 二阶自动发现：写入 / 清空（新扫描开始时清空）
  setSecondOrderDiscovery: (
    d: { candidates: string[]; confirmed: string[]; storePoints?: { param: string; storeKind?: string | null }[] } | null,
  ) => void;
  clearSecondOrderDiscovery: () => void;
  // 实时注入点：写入 / 清空（新扫描开始时清空上一次）
  setDiscoveredPoints: (p: InjectionPoint[]) => void;
  clearDiscoveredPoints: () => void;
  // 实时目标 URL：写入（scan_started）/ 清空
  setTargetUrl: (u: string | null) => void;
  // 已确认漏洞注入点 id：增量收集（detection_found）/ 不清空（reset 统一清空）
  addConfirmedVulnPointId: (id: string) => void;
  clearConfirmedVulnPointIds: () => void;
  // 扫描完成时写入完整报告快照（去重、置顶、截断 100）
  saveScanToHistory: (report: ReportModel) => void;
  // 软性删除单条（仅从数组过滤，写回 localStorage）
  removeHistory: (scanId: string) => void;
  // SSE 实时事件流连接状态（驱动进度区「实时已连接/重连中」指示）
  sseStatus: 'idle' | 'connecting' | 'open' | 'reconnecting';
  setSseStatus: (s: 'idle' | 'connecting' | 'open' | 'reconnecting') => void;
  reset: () => void;
}

export const useScanStore = create<ScanState>((set) => ({
  scanId: null,
  status: 'pending',
  engine: 'builtin',
  report: null,
  events: [],
  history: loadHistory(),
  wafSuggestion: null,
  secondOrderDiscovery: null,
  discoveredPoints: [],
  targetUrl: null,
  confirmedVulnPointIds: [],
  scanConcurrency: null,
  setScanId: (id) => set({ scanId: id }),
  setEngine: (e) => set({ engine: e }),
  setStatus: (s) => set({ status: s }),
  setReport: (r) => set({ report: r }),
  addEvent: (e) => set((st) => ({ events: [...st.events, e].slice(-300) })),
  clearEvents: () => set({ events: [] }),
  setWafSuggestion: (s) => set({ wafSuggestion: s }),
  clearWafSuggestion: () => set({ wafSuggestion: null }),
  setSecondOrderDiscovery: (d) => set({ secondOrderDiscovery: d }),
  clearSecondOrderDiscovery: () => set({ secondOrderDiscovery: null }),
  setDiscoveredPoints: (p) => set({ discoveredPoints: p }),
  clearDiscoveredPoints: () => set({ discoveredPoints: [] }),
  setTargetUrl: (u) => set({ targetUrl: u }),
  addConfirmedVulnPointId: (id) =>
    set((st) => (st.confirmedVulnPointIds.includes(id) ? st : { confirmedVulnPointIds: [...st.confirmedVulnPointIds, id] })),
  clearConfirmedVulnPointIds: () => set({ confirmedVulnPointIds: [] }),
  setScanConcurrency: (n) => set({ scanConcurrency: n }),
  saveScanToHistory: (report) =>
    set((st) => {
      const record: HistoryRecord = {
        schemaVersion: 1,
        scanId: report.scanId,
        target: report.target.baseUrl,
        riskLevel: report.riskLevel,
        finishedAt: report.finishedAt,
        report,
      };
      // 按 scanId 去重并置顶，截断至 100 条
      const next = [record, ...st.history.filter((h) => h.scanId !== report.scanId)].slice(
        0,
        HISTORY_LIMIT
      );
      persistHistory(next);
      return { history: next };
    }),
  removeHistory: (scanId) =>
    set((st) => {
      const next = st.history.filter((h) => h.scanId !== scanId);
      persistHistory(next);
      return { history: next };
    }),
  sseStatus: 'idle',
  setSseStatus: (s) => set({ sseStatus: s }),
  reset: () =>
    set({ scanId: null, status: 'pending', report: null, events: [], wafSuggestion: null, secondOrderDiscovery: null, discoveredPoints: [], targetUrl: null, confirmedVulnPointIds: [], scanConcurrency: null, sseStatus: 'idle' }),
}));
