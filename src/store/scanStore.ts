import { create } from 'zustand';
import type { ReportModel, ScanEvent, ScanStatus, HistoryRecord, EngineType, WafDetectedPayload } from '../shared/types';

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

// 落盘前脱敏（P1-U8）：剥离 target.config 中的认证（basic/cookie/headers）与代理配置，
// 避免明文凭据存进 localStorage。返回浅拷贝，不污染内存中的 report。
function sanitizeReportForStorage(report: ReportModel): ReportModel {
  if (!report?.target?.config) return report;
  const { auth, proxy, ...restConfig } = report.target.config;
  return {
    ...report,
    target: {
      ...report.target,
      config: {
        ...restConfig,
        // 认证/代理脱敏：置 null 表示「不落盘明文」，保留「曾配置过」语义通过 masked 布尔无法表达，
        // 直接置 null（历史回溯不依赖认证信息，重扫时由用户重新填写）。
        auth: null,
        proxy: null,
      } as ReportModel['target']['config'],
    },
  };
}

// 扫描会话状态（zustand 单一数据源）
interface ScanState {
  scanId: string | null;
  // P0-1 新增：本次扫描「启动时」的引擎快照（与 scanId 同生命周期）。
  // 与 UI 选择字段 engine 分离：engine 反映用户在面板上的选择（可在未运行时切换），
  // scanEngine 在 startSession 时原子写入，SSE 订阅/停止/报告拉取都按它选端点，
  // 扫描中途切换 UI 引擎不再影响正在进行的会话。
  scanEngine: EngineType | null;
  status: ScanStatus;
  engine: EngineType;
  report: ReportModel | null;
  events: ScanEvent[];
  // H2：进度聚合（增量维护，独立于 events 滑窗）
  // progressTotal：最近一次 point_discovered 报告的注入点总数；
  // processedPointIds：已测试/跳过/命中的 pointId 集合（对象做不可变集合用）；
  // processedCount：[P1-FIX] 已处理点数的增量数字（避免页面订阅 processedPointIds 对象
  //   —— 每事件新引用触发整页重渲染，且每次 Object.keys().length 为 O(n) 扫描）。
  progressTotal: number;
  processedPointIds: Record<string, true>;
  processedCount: number;
  history: HistoryRecord[];
  // WAF 识别建议（waf_detected 事件载荷；仅推荐，不自动套用）
  wafSuggestion: WafDetectedPayload | null;
  setScanId: (id: string) => void;
  setEngine: (e: EngineType) => void;
  setStatus: (s: ScanStatus) => void;
  setReport: (r: ReportModel) => void;
  // P0-1 新增：原子写入「scanId + 启动时引擎快照 + running」。
  // 取代 useScan.startScan 成功后原「setScanId + setStatus」两次写入，
  // 避免中间态（scanId 已变而 scanEngine 未变导致订阅/停止选错端点）。
  startSession: (scanId: string, engine: EngineType) => void;
  addEvent: (e: ScanEvent) => void;
  clearEvents: () => void;
  // WAF 建议：写入 / 清空（新扫描开始时清空，避免残留上一次建议）
  setWafSuggestion: (s: WafDetectedPayload | null) => void;
  clearWafSuggestion: () => void;
  // 扫描完成时写入完整报告快照（去重、置顶、截断 100）
  saveScanToHistory: (report: ReportModel) => void;
  // 软性删除单条（仅从数组过滤，写回 localStorage）
  removeHistory: (scanId: string) => void;
  reset: () => void;
}

export const useScanStore = create<ScanState>((set) => ({
  scanId: null,
  scanEngine: null,
  status: 'pending',
  engine: 'builtin',
  report: null,
  events: [],
  progressTotal: 0,
  processedPointIds: {},
  processedCount: 0,
  history: loadHistory(),
  wafSuggestion: null,
  setScanId: (id) => set({ scanId: id }),
  setEngine: (e) => set({ engine: e }),
  setStatus: (s) => set({ status: s }),
  setReport: (r) => set({ report: r }),
  startSession: (scanId, engine) => set({ scanId, scanEngine: engine, status: 'running' }),
  // H2：事件追加 + 进度聚合增量更新。聚合值独立于 events 滑窗存活，
  // 长扫描中早期 point_discovered 被截断后进度条不再归零。
  addEvent: (e) =>
    set((st) => {
      let { progressTotal } = st;
      let processedPointIds = st.processedPointIds;
      let processedCount = st.processedCount;
      if (e.type === 'point_discovered') {
        const pts = (e.payload as { points?: unknown[] } | undefined)?.points;
        if (Array.isArray(pts)) progressTotal = pts.length;
      } else if (
        e.type === 'point_testing' || e.type === 'point_skipped' || e.type === 'detection_found'
      ) {
        const pid = (e.payload as { pointId?: string } | undefined)?.pointId;
        if (pid && !(pid in processedPointIds)) {
          processedPointIds = { ...processedPointIds, [pid]: true };
          processedCount += 1; // 增量计数：页面订阅数字而非对象，避免高频 SSE 整页重渲染
        }
      }
      return { events: [...st.events, e].slice(-300), progressTotal, processedPointIds, processedCount };
    }),
  clearEvents: () => set({ events: [], progressTotal: 0, processedPointIds: {}, processedCount: 0 }),
  setWafSuggestion: (s) => set({ wafSuggestion: s }),
  clearWafSuggestion: () => set({ wafSuggestion: null }),
  saveScanToHistory: (report) =>
    set((st) => {
      // P1-U8：落盘前剥离认证/代理等敏感配置，避免明文凭据存进 localStorage
      const safeReport = sanitizeReportForStorage(report);
      const record: HistoryRecord = {
        schemaVersion: 1,
        scanId: safeReport.scanId,
        target: safeReport.target.baseUrl,
        riskLevel: safeReport.riskLevel,
        finishedAt: safeReport.finishedAt,
        report: safeReport,
      };
      // 按 scanId 去重并置顶，截断至 100 条
      const next = [record, ...st.history.filter((h) => h.scanId !== safeReport.scanId)].slice(
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
  // P0-1：reset 同时清空 scanEngine 快照与进度聚合
  reset: () =>
    set({
      scanId: null, scanEngine: null, status: 'pending', report: null,
      events: [], wafSuggestion: null, progressTotal: 0, processedPointIds: {}, processedCount: 0,
    }),
}));
