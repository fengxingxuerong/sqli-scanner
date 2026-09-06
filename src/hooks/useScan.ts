// 变更点：
//  P0-1：startScan 成功后改调 store.startSession 原子写入「scanId + 启动时引擎快照 + running」；
//        stopScan / getReport 按启动时引擎快照（scanEngine，历史记录按记录内 engine）选端点，
//        不再依赖可能已被用户切换的 UI engine。
//  P1-1：getReport 增加请求竞态守卫（模块级 latestReportRequestId）——并发请求只允许
//        「最新一次请求」写 store，过期响应丢弃，防止快速切换 /report/A → /report/B 时
//        旧响应覆盖新报告。
//  P1-4：本 Hook 不再通过 useScanStore() 订阅整个 store（原实现会让调用方组件随每个
//        SSE 事件重渲染），动作一律经 useScanStore.getState() 取用（zustand action 引用稳定）。

import { useCallback } from 'react';
import { apiClient } from '../shared/apiClient';
import { ApiError } from '../shared/apiClient';
import { useScanStore } from '../store/scanStore';
import { API_BASE } from '../shared/apiClient';
import { tauriBridge } from '../shared/tauriBridge';
import { DEFAULT_CONFIG, DEFAULT_SQLMAP_CONFIG } from '../shared/constants';
import i18n from '../i18n';
import type {
  ReportModel,
  ScanConfig,
  EngineType,
  SqlmapConfig,
  SqlmapReportData,
  SqlmapVulnEntry,
  MethodType,
  RiskLevel,
  Target,
} from '../shared/types';
import { ErrorCode } from '../shared/types';

// P1-1：模块级「最新报告请求」标记。getReport 并发时（快速切换报告页），
// 响应返回后若 latestReportRequestId 已不是本次 scanId，说明已被更新的请求取代，
// 丢弃该响应，避免旧报告覆盖 store 中较新的报告。
let latestReportRequestId = '';

// 包装 sqlmap 桥原始报告 {logs,vulns} 为前端可渲染的 ReportModel（与内置引擎报告同构）
export function wrapSqlmapReport(
  scanId: string,
  raw: Partial<SqlmapReportData>,
  meta?: { targetUrl?: string; method?: MethodType; riskLevel?: RiskLevel }
): ReportModel {
  const logs = Array.isArray(raw.logs) ? raw.logs : [];
  const vulns: SqlmapVulnEntry[] = Array.isArray(raw.vulns) ? raw.vulns : [];
  // 无明确风险标注时：命中注入点视为高危，否则低危
  const riskLevel: RiskLevel = meta?.riskLevel ?? (vulns.length ? 'High' : 'Low');
  const target: Target = {
    id: scanId,
    baseUrl: meta?.targetUrl ?? '',
    method: meta?.method ?? 'GET',
    bodyParams: {},
    cookieParams: {},
    headerParams: {},
    config: { ...DEFAULT_CONFIG },
  };
  return {
    scanId,
    engine: 'sqlmap',
    target,
    startedAt: logs[0]?.ts ?? new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    dbms: null,
    points: [],
    vulns: [],
    data: null,
    riskLevel,
    summary: {},
    sqlmap: { status: raw.status ?? 'completed', logs, vulns },
  } as ReportModel;
}

// 扫描控制 Hook：封装 start/stop/getReport/export（混合架构：自带引擎 / sqlmap 后端）
export function useScan() {
  // 启动扫描（按 engine 选择后端与请求体）
  // [P0-FIX] 所有函数用 useCallback([]) 包裹：它们内部全部通过 useScanStore.getState()
  // 取值，不依赖闭包变量，空依赖数组安全。否则每次渲染产生新引用，导致 ScanWizard
  // 的 React.memo 失效，SSE 高频期间整棵表单子树无效重渲染。
  const startScan = useCallback(async (payload: {
    engine: EngineType;
    url: string;
    method: MethodType;
    bodyParams?: Record<string, string>;
    cookieParams?: Record<string, string>;
    headerParams?: Record<string, string>;
    config: ScanConfig;
    sqlmapConfig?: SqlmapConfig;
  }): Promise<string> => {
    const st = useScanStore.getState();
    // 重复扫描守卫：正在运行时不允许再次启动（防止并发槽耗尽 + UI 混乱）
    if (st.status === 'running' && st.scanId) {
      throw new Error(i18n.t('common.scanRunning'));
    }
    // 同步 UI 上的引擎选择（此时扫描尚未开始，scanEngine 仍为 null）
    st.setEngine(payload.engine);

    try {
      // ── 高级模式：后端 sqlmap ──
      if (payload.engine === 'sqlmap') {
        const target: Record<string, unknown> = {
          url: payload.url,
          method: payload.method,
        };
        if (
          payload.method === 'POST' &&
          payload.bodyParams &&
          Object.keys(payload.bodyParams).length
        ) {
          target.data = new URLSearchParams(payload.bodyParams).toString();
        }
        const cookie = payload.config.auth?.cookie;
        if (cookie) target.cookie = cookie;
        // Basic Auth 透传：sqlmap --auth-type=basic + --auth-cred=user:pass（或走 header 注入）
        const basic = payload.config.auth?.basic;
        if (basic && basic.username) {
          const cred = `${basic.username}:${basic.password ?? ''}`;
          // sqlmap 识别 Authorization header 形态，直接拼入 target.headers
          const existingHeaders = target.headers ? target.headers + '\n' : '';
          target.headers = existingHeaders + `Authorization: Basic ${btoa(cred)}`;
        }
        const headers = payload.config.auth?.headers;
        if (headers && Object.keys(headers).length) {
          // [P1-FIX] 追加而非覆盖：原实现直接赋值会丢掉 Basic Auth 的 Authorization 头
          const headerText = Object.entries(headers)
            .map(([k, v]) => `${k}: ${v}`)
            .join('\n');
          target.headers = target.headers ? `${target.headers}\n${headerText}` : headerText;
        }
        // P0-U2：透传 sqlmap 配置（含 proxy/timeoutMs/retry/randomUA）。
        // 代理留空时复用内置面板「扫描配置」里的代理，避免 sqlmap 模式下该配置失效。
        const sqlmap: SqlmapConfig = {
          ...(payload.sqlmapConfig ?? DEFAULT_SQLMAP_CONFIG),
          proxy: payload.sqlmapConfig?.proxy ?? payload.config.proxy ?? null,
        };
        // S11：ScanConfig 的 prefix/suffix（对标 sqlmap --prefix/--suffix）一并透传，
        // 由后端 buildArgs 消费；空串省略。
        const config: Record<string, unknown> = { sqlmap };
        if (payload.config.prefix) config.prefix = payload.config.prefix;
        if (payload.config.suffix) config.suffix = payload.config.suffix;
        const data = await apiClient.post<{ scanId: string }>('/sqlmap/start', {
          target,
          config,
        });
        // P0-1：scanId 与启动时引擎快照原子写入（含 status=running）
        st.startSession(data.scanId, 'sqlmap');
        return data.scanId;
      }

      // ── 默认模式：自带引擎 ──
      const data = await apiClient.post<{ scanId: string }>('/scan/start', payload);
      st.startSession(data.scanId, 'builtin');
      return data.scanId;
    } catch (e: unknown) {
      // API 失败时设置错误状态，让 UI 能感知并展示
      st.setStatus('error');
      throw e;
    }
  }, []);

  // 停止扫描（P0-1：按启动时引擎快照选端点，而非当前 UI 选择）
  const stopScan = useCallback(async (scanId: string): Promise<void> => {
    const st = useScanStore.getState();
    // 仅当停的是「当前会话扫描」时用 scanEngine 快照；否则回退 UI 选择
    const engine = st.scanId === scanId && st.scanEngine ? st.scanEngine : st.engine;
    const base = engine === 'sqlmap' ? '/sqlmap' : '/scan';
    try {
      await apiClient.post(`${base}/${scanId}/stop`);
    } catch {
      // API 失败仍设 stopped（best-effort），避免 UI 卡在 running
    }
    st.setStatus('stopped');
  }, []);

  // [P0-FIX] 暂停扫描（仅内置引擎支持；sqlmap 模式暂停透传后端 sqlmapRoutes 若实现）
  const pauseScan = useCallback(async (scanId: string): Promise<void> => {
    const st = useScanStore.getState();
    const engine = st.scanId === scanId && st.scanEngine ? st.scanEngine : st.engine;
    const base = engine === 'sqlmap' ? '/sqlmap' : '/scan';
    try {
      await apiClient.post(`${base}/${scanId}/pause`);
      st.setStatus('paused');
    } catch {
      // 失败保持当前状态（best-effort）
    }
  }, []);

  // 恢复暂停的扫描
  const resumeScan = useCallback(async (scanId: string): Promise<void> => {
    const st = useScanStore.getState();
    const engine = st.scanId === scanId && st.scanEngine ? st.scanEngine : st.engine;
    const base = engine === 'sqlmap' ? '/sqlmap' : '/scan';
    try {
      await apiClient.post(`${base}/${scanId}/resume`);
      st.setStatus('running');
    } catch {
      // 失败保持当前状态（best-effort）
    }
  }, []);

  // 获取完整报告（按引擎路由：内置引擎 /scan/:id/report，sqlmap /sqlmap/:id/report）
  // [P0-FIX] opts.force=true 时跳过 store 缓存直接请求后端：
  // 原实现「st.report?.scanId === scanId 直接复用」使报告页刷新按钮永远走缓存（静默 no-op），
  // 扫描结束后的增量数据（如仍在写入的提取结果）无法刷新获取。
  const getReport = useCallback(async function getReport(
    scanId: string,
    opts?: { force?: boolean }
  ): Promise<ReportModel | null> {
    // P1-1：登记为「最新请求」，响应返回时若已被取代则丢弃
    latestReportRequestId = scanId;
    const st = useScanStore.getState();
    // 当前会话已有同 id 报告（扫描完成自动写入 / 历史回溯快照）直接复用，
    // 避免 sqlmap 历史记录回溯时向后端误发 /scan 路由（后端会话已回收）
    if (!opts?.force && st.report?.scanId === scanId) return st.report;

    // P0-1：引擎判定优先级 ——
    //   ① 当前会话扫描（store.scanId === scanId）→ 用启动时快照 scanEngine；
    //   ② 历史快照（本地持久化记录）→ 用记录内 report.engine（sqlmap 记录回溯不再误发 /scan）；
    //   ③ 均不匹配 → 回退当前 UI 选择 engine。
    let engine: EngineType = st.engine;
    if (st.scanId === scanId && st.scanEngine) {
      engine = st.scanEngine;
    } else {
      const rec = st.history.find((h) => h.scanId === scanId);
      if (rec?.report?.engine) engine = rec.report.engine;
    }
    const base = engine === 'sqlmap' ? '/sqlmap' : '/scan';
    try {
      let r: ReportModel;
      if (engine === 'sqlmap') {
        const raw = await apiClient.get<Partial<SqlmapReportData>>(`${base}/${scanId}/report`);
        r = wrapSqlmapReport(scanId, raw);
      } else {
        r = await apiClient.get<ReportModel>(`${base}/${scanId}/report`);
      }
      // P1-1：过期响应（期间又发起了更新的报告请求）直接丢弃，不写 store
      if (latestReportRequestId !== scanId) return null;
      st.setReport(r);
      return r;
    } catch (e) {
      // SCAN_NOT_FOUND：扫描不存在/已结束，返回 null 让 UI 显示「未找到」；
      // 其他错误（网络异常等）向上抛出，让调用方展示真实错误信息而非误报「未找到」。
      if (e instanceof ApiError && e.code === ErrorCode.SCAN_NOT_FOUND) return null;
      throw e;
    }
  }, []);

  // 导出报告（json/html/csv/markdown/db-json）：统一走 tauriBridge.saveFile —— Web 版 blob 下载，Tauri 版 dialog 落盘。
  // 直接 fetch 原始内容（导出端点返回裸内容，非 {code,data,message} 包装，故不走 apiClient 解包）。
  // db-json：仅拖库数据部分（report.data），对标 sqlmap --dump 产物。
  const exportReport = useCallback(async (
    scanId: string,
    format: 'json' | 'html' | 'csv' | 'markdown' | 'db-json'
  ): Promise<void> => {
    const url = `${API_BASE}/scan/${scanId}/report/export?format=${format}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(i18n.t('common.exportFailed', { status: res.status }));
    const content = await res.text();
    const mimeMap = {
      html: 'text/html; charset=utf-8',
      csv: 'text/csv; charset=utf-8',
      markdown: 'text/markdown; charset=utf-8',
      json: 'application/json; charset=utf-8',
      'db-json': 'application/json; charset=utf-8',
    } as const;
    const mime = mimeMap[format];
    const fileExt = format === 'db-json' ? 'db.json' : format;
    await tauriBridge.saveFile(`report_${scanId}.${fileExt}`, content, mime);
  }, []);

  return { startScan, stopScan, pauseScan, resumeScan, getReport, exportReport };
}
