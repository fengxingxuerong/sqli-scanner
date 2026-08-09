import { useEffect, useRef } from 'react';
import { useScanStore } from '../store/scanStore';
import { useScan } from './useScan';
import { API_BASE } from '../shared/apiClient';
import type { ScanEvent } from '../shared/types';

// SSE 订阅 Hook：订阅指定扫描的实时进度事件并写入 store
export function useEvents(scanId: string | null) {
  const { addEvent, setStatus, setReport, clearEvents, setWafSuggestion, clearWafSuggestion, setSecondOrderDiscovery, clearSecondOrderDiscovery, setDiscoveredPoints, clearDiscoveredPoints, setTargetUrl, addConfirmedVulnPointId, clearConfirmedVulnPointIds, saveScanToHistory, engine, setSseStatus } =
    useScanStore();
  const { getReport } = useScan();
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!scanId) return;
    clearEvents();
    clearWafSuggestion(); // 新扫描开始，清空上一次 WAF 建议
    clearSecondOrderDiscovery(); // 清空上一次二阶自动发现结果
    clearDiscoveredPoints(); // 清空上一次实时注入点
    clearConfirmedVulnPointIds(); // 清空上一次已确认漏洞高亮
    setTargetUrl(null); // 清空上一次目标 URL

    // sqlmap 后端走 /sqlmap 命名空间，自带引擎走 /scan
    const ns = engine === 'sqlmap' ? 'sqlmap' : 'scan';
    const es = new EventSource(`${API_BASE}/${ns}/${scanId}/events`);
    esRef.current = es;
    setSseStatus('connecting');

    es.onmessage = (ev) => {
      let data: ScanEvent;
      try {
        data = JSON.parse(ev.data) as ScanEvent;
      } catch {
        return;
      }
      addEvent(data);

      // WAF 指纹识别结果（识别到 WAF 时）：写入 store 供扫描页展示推荐组合（仅推荐，不自动套用）
      if (data.type === 'waf_detected' && data.payload) {
        setWafSuggestion(data.payload);
      }

      // 二阶触发页自动发现结果：写入 store 供扫描页实时展示（仅展示，不阻断主扫描）
      if (data.type === 'second_order_discovery' && data.payload) {
        setSecondOrderDiscovery(data.payload);
      }

      // 扫描目标 URL（scan_started 载荷 target.baseUrl，供扫描页实时全局拓扑根节点）
      if (data.type === 'scan_started' && data.payload?.target) {
        setTargetUrl(data.payload.target.baseUrl);
      }

      // 解析目标后回传的全部注入点（point_discovered 载荷 points，供扫描页实时全局拓扑）
      if (data.type === 'point_discovered' && data.payload?.points) {
        setDiscoveredPoints(data.payload.points);
      }

      // 已确认漏洞（detection_found 载荷含 pointId，与 InjectionPoint.id 对齐）：
      // 增量收集供扫描页实时拓扑对命中参数节点红框高亮
      if (data.type === 'detection_found' && data.payload?.pointId) {
        addConfirmedVulnPointId(String(data.payload.pointId));
      }

      if (data.type === 'scan_completed') {
        setStatus('completed');
        if (engine === 'builtin' && data.payload) {
          setReport(data.payload);
          // 扫描完成：持久化完整报告快照到本地历史库（支持离线回溯）
          saveScanToHistory(data.payload);
        } else if (engine === 'sqlmap') {
          // sqlmap 完成事件不带报告体：单独拉取并落地历史（与 builtin 一致，可离线回溯）
          getReport(scanId).then((r) => {
            if (r) saveScanToHistory(r);
          });
        }
        es.close();
      } else if (data.type === 'scan_stopped') {
        setStatus('stopped');
        es.close();
      } else if (data.type === 'scan_error') {
        setStatus('error');
        es.close();
      }
    };

    // 连接建立：标记为已连接（驱动进度区实时指示）
    es.onopen = () => setSseStatus('open');
    // SSE 错误：浏览器会自动重连，标记为「重连中」而非断开（避免误报离线）
    es.onerror = () => setSseStatus('reconnecting');

    return () => {
      es.close();
    };
  }, [scanId, engine, addEvent, setStatus, setReport, clearEvents, clearWafSuggestion, clearSecondOrderDiscovery, setDiscoveredPoints, clearDiscoveredPoints, setTargetUrl, addConfirmedVulnPointId, clearConfirmedVulnPointIds]);
}
