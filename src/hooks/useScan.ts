import { apiClient } from '../shared/apiClient';
import { useScanStore } from '../store/scanStore';
import { API_BASE } from '../shared/apiClient';
import type {
  ReportModel,
  ScanConfig,
  EngineType,
  SqlmapConfig,
} from '../shared/types';
import { DEFAULT_SQLMAP_CONFIG } from '../shared/constants';

// 扫描控制 Hook：封装 start/stop/getReport/export（混合架构：自带引擎 / sqlmap 后端）
export function useScan() {
  const { setScanId, setStatus, setReport, setEngine, setScanConcurrency } = useScanStore();

  // 启动扫描（按 engine 选择后端与请求体）
  async function startScan(payload: {
    engine: EngineType;
    url: string;
    method: 'GET' | 'POST';
    bodyParams?: Record<string, string>;
    cookieParams?: Record<string, string>;
    headerParams?: Record<string, string>;
    config: ScanConfig;
    sqlmapConfig?: SqlmapConfig;
  }): Promise<string> {
    setEngine(payload.engine);

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
      const headers = payload.config.auth?.headers;
      if (headers && Object.keys(headers).length) {
        target.headers = Object.entries(headers)
          .map(([k, v]) => `${k}: ${v}`)
          .join('\n');
      }
      const data = await apiClient.post<{ scanId: string }>('/sqlmap/start', {
        target,
        config: { sqlmap: payload.sqlmapConfig ?? DEFAULT_SQLMAP_CONFIG },
      });
      setScanId(data.scanId);
      setScanConcurrency(payload.sqlmapConfig?.threads ?? 1);
      setStatus('running');
      return data.scanId;
    }

    // ── 默认模式：自带引擎 ──
    const data = await apiClient.post<{ scanId: string }>('/scan/start', payload);
    setScanId(data.scanId);
    setScanConcurrency(payload.config.concurrency ?? 1);
    setStatus('running');
    return data.scanId;
  }

  // 停止扫描（按 engine 选择端点）
  async function stopScan(scanId: string): Promise<void> {
    const engine = useScanStore.getState().engine;
    const base = engine === 'sqlmap' ? '/sqlmap' : '/scan';
    await apiClient.post(`${base}/${scanId}/stop`);
    setStatus('stopped');
  }

  // 获取完整报告（按引擎选择后端端点：sqlmap 走 /sqlmap，自带引擎走 /scan）
  async function getReport(scanId: string): Promise<ReportModel | null> {
    try {
      const base = useScanStore.getState().engine === 'sqlmap' ? '/sqlmap' : '/scan';
      const r = await apiClient.get<ReportModel>(`${base}/${scanId}/report`);
      setReport(r);
      return r;
    } catch {
      return null;
    }
  }

  // 导出报告（json/html）；Web 版用浏览器下载，Tauri 版走桥接落盘
  function exportReport(scanId: string, format: 'json' | 'html'): void {
    const url = `${API_BASE}/scan/${scanId}/report/export?format=${format}`;
    window.open(url, '_blank');
  }

  return { startScan, stopScan, getReport, exportReport };
}
