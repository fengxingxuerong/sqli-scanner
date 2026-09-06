// 变更点：
//  P0-1：SSE 命名空间改按「启动时引擎快照」判定（scanEngine ?? engine），deps 移除 engine ——
//        扫描中途切换 UI 引擎不再重建订阅 / 清空事件流 / 指错命名空间。
//  P1-3：手动接管重连 —— onerror 关闭当前连接并指数退避重开（1s/2s/4s/8s/8s，上限 5 次）；
//        onopen 标记重连成功并「拉报告对账」（断线期间可能错过终态事件，按报告终态补写）；
//        超限置 status=error 并追加一条 scan_error 事件提示（仅当仍处于 running 时）。
//  P1-4：改用选择器订阅（仅订阅稳定 action 引用，不订阅 engine/status 等变化值），
//        避免 ScanPage 随每个 SSE 事件整树重渲染。
//  P1-5：sqlmap 完成态异步拉报告前捕获 scanId 快照，写入前校验仍处于同一会话，
//        避免旧扫描报告污染新会话（store.scanId 为空时视为无会话、放行，兼容测试直呼 Hook）。
//  P2-SSE：断线重连续传 —— 记录服务端事件 seq 游标，重开连接时带 lastEventId 参数，
//        服务端按环形回放缓冲补发断线窗口内错过的事件（消除进度/时间线空洞）；
//        「扫描不存在或已结束」型 scan_error 先拉报告对账再定状态（已完成扫描不再被误标 error）。

import { useEffect } from 'react';
import { useScanStore } from '../store/scanStore';
import { API_BASE, apiClient } from '../shared/apiClient';
import type { ScanEvent, SqlmapReportData, MethodType, ReportModel } from '../shared/types';
import { ErrorCode } from '../shared/types';
import { wrapSqlmapReport } from './useScan';
import i18n from '../i18n';

// P1-3：重连退避上限（连续失败次数；每次成功连接后归零）
const MAX_RETRIES = 5;

// SSE 订阅 Hook：订阅指定扫描的实时进度事件并写入 store
export function useEvents(scanId: string | null) {
  // P1-4：仅订阅稳定 action 引用（zustand create() 创建一次后引用恒定，选择器不触发重渲染）
  const addEvent = useScanStore((s) => s.addEvent);
  const setStatus = useScanStore((s) => s.setStatus);
  const setReport = useScanStore((s) => s.setReport);
  const clearEvents = useScanStore((s) => s.clearEvents);
  const setWafSuggestion = useScanStore((s) => s.setWafSuggestion);
  const clearWafSuggestion = useScanStore((s) => s.clearWafSuggestion);
  const saveScanToHistory = useScanStore((s) => s.saveScanToHistory);

  useEffect(() => {
    if (!scanId) return;
    // [P0-FIX] 同会话重挂载（扫描进行中切走页面再返回，路由懒加载卸载→重挂载）不清空进度：
    // 原实现无条件 clearEvents() + clearWafSuggestion()，返回后进度条归零、已测点数丢失，
    // 且重连从 lastSeq=0 重放造成时间线重复行。仅当「新会话 / 无事件 / 事件属于其它会话」才清空
    // （events[0].scanId 归属判断覆盖「store.scanId 已切新值但事件流仍是旧扫描」的时序）。
    const cur0 = useScanStore.getState();
    const sameSession =
      cur0.scanId === scanId &&
      cur0.events.length > 0 &&
      cur0.events[0].scanId === scanId;
    if (!sameSession) {
      clearEvents();
      clearWafSuggestion(); // 新扫描开始，清空上一次 WAF 建议
    }

    // P0-1：命名空间按「启动时引擎快照」判定。
    // scanEngine 由 startSession 原子写入（与 scanId 同时变化，故无需进 deps，效果内
    // 经 getState() 读取即可拿到订阅时刻的快照）；scanEngine 为 null（测试直呼/旧路径）
    // 时回退当前 UI 选择 engine。
    const st0 = useScanStore.getState();
    const nsEngine = st0.scanEngine ?? st0.engine;
    const ns = nsEngine === 'sqlmap' ? 'sqlmap' : 'scan';
    const token = (() => {
      const env = import.meta.env.VITE_SCAN_API_TOKEN as string | undefined;
      if (env) return env;
      try { return localStorage.getItem('scanApiToken') || ''; } catch { return ''; }
    })();

    let disposed = false;
    let es: EventSource | null = null;
    let backoffTimer: number | null = null;
    let retryCount = 0;
    let firstOpen = true;
    // P2-SSE：已收到的最大事件序号（跨重连保留），0 表示从头订阅
    // [P0-FIX] 同会话重挂载时从 store 已有事件恢复游标，避免服务端整段回放重复入列
    let lastSeq = sameSession
      ? cur0.events.reduce((m, e) => (typeof e.seq === 'number' && e.seq > m ? e.seq : m), 0)
      : 0;

    // P1-3：重连成功后拉报告对账 —— 断线期间可能错过终态事件（scan_completed 等），
    // 若报告已终态（builtin: finishedAt 非空；sqlmap: status !== running）则补写终态，
    // 避免 UI 永久停在「扫描中」。
    // M10：并发闸门 —— 快速连断连时可能同时触发多次 reconcile，避免同一 scanId 双写终态
    let reconciling = false;
    const reconcile = async () => {
      if (reconciling) return;
      reconciling = true;
      try {
        const st = useScanStore.getState();
        if (st.scanId && st.scanId !== scanId) return; // 会话已切换，丢弃
        const engine = st.scanEngine ?? st.engine;
        if (engine === 'sqlmap') {
          const raw = await apiClient.get<Partial<SqlmapReportData>>(`/sqlmap/${scanId}/report`);
          const status = raw?.status;
          if (status && status !== 'running') {
            const started = useScanStore.getState().events.find((e) => e.type === 'scan_started');
            const t = (started?.payload as { target?: { url?: string; method?: MethodType } } | undefined)?.target;
            const wrapped = wrapSqlmapReport(scanId, raw, { targetUrl: t?.url, method: t?.method });
            const cur = useScanStore.getState();
            if (cur.scanId && cur.scanId !== scanId) return;
            if (cur.status === 'running') {
              setReport(wrapped);
              saveScanToHistory(wrapped);
              setStatus(
                status === 'error' ? 'error' : status === 'stopped' || status === 'killed' ? 'stopped' : 'completed'
              );
            }
          }
        } else {
          const r = await apiClient.get<ReportModel>(`/scan/${scanId}/report`);
          const cur = useScanStore.getState();
          if (cur.scanId && cur.scanId !== scanId) return;
          if (r?.finishedAt && cur.status === 'running') {
            setReport(r);
            saveScanToHistory(r);
            setStatus('completed');
          }
        }
      } catch {
        // 报告拉取失败（会话已回收 / 后端未就绪）：静默，由重连超限逻辑兜底
      } finally {
        reconciling = false;
      }
    };

    const open = () => {
      if (disposed) return;
      // P2-SSE：每次（重）开连接按当前游标构建 URL ——
      // token 走 query（EventSource 无法设自定义头），lastEventId 供服务端回放断线窗口内错过的事件
      const qs: string[] = [];
      if (token) qs.push(`token=${encodeURIComponent(token)}`);
      if (lastSeq > 0) qs.push(`lastEventId=${lastSeq}`);
      // [P2-FIX] 实例引用保护：onerror/onopen 回调按 current 判定归属，
      // 浏览器对已关闭实例补发的迟到 error 不会误关/误处理当前连接（防双连接/重复计数）。
      const current = new EventSource(`${API_BASE}/${ns}/${scanId}/events${qs.length ? `?${qs.join('&')}` : ''}`);
      es = current;

      current.onopen = () => {
        if (es !== current) return; // 已被替换/关闭
        retryCount = 0;
        if (!firstOpen) {
          // 非首次打开 = 重连成功：对账，可能补回断线期间错过的终态
          void reconcile();
        }
        firstOpen = false;
      };

      current.onmessage = (ev) => {
        let data: ScanEvent;
        try {
          data = JSON.parse(ev.data) as ScanEvent;
        } catch {
          return; // 坏载荷跳过，不中断连接
        }
        // P2-SSE：推进重连游标（服务端为每条事件附带单调递增 seq）
        if (typeof (data as { seq?: number }).seq === 'number' && Number.isFinite((data as { seq?: number }).seq)) {
          lastSeq = Math.max(lastSeq, (data as { seq?: number }).seq as number);
        }
        addEvent(data);

        // WAF 指纹识别结果（识别到 WAF 时）：写入 store 供扫描页展示推荐组合（仅推荐，不自动套用）
        if (data.type === 'waf_detected' && data.payload) {
          setWafSuggestion(data.payload);
        }

        if (data.type === 'scan_completed') {
          setStatus('completed');
          if (nsEngine === 'builtin' && data.payload) {
            setReport(data.payload);
            // 扫描完成：持久化完整报告快照到本地历史库（支持离线回溯）
            saveScanToHistory(data.payload);
          } else if (nsEngine === 'sqlmap') {
            // P0-U1 闭环：sqlmap 模式拉取最终报告（日志 + 命中漏洞），
            // 包装为前端可渲染视图并落库，使高级模式从「只能看实时日志」变为可回溯/可导出。
            // P1-5：写入前校验仍处于同一扫描会话，避免旧扫描报告污染新会话。
            void (async () => {
              try {
                const raw = await apiClient.get<Partial<SqlmapReportData>>(
                  `/sqlmap/${scanId}/report`
                );
                // sqlmap 报告不含目标信息，从 scan_started 事件载荷里取目标 URL/方法
                const started = useScanStore
                  .getState()
                  .events.find((e) => e.type === 'scan_started');
                const t = (started?.payload as { target?: { url?: string; method?: MethodType } } | undefined)?.target;
                const wrapped = wrapSqlmapReport(scanId, raw, {
                  targetUrl: t?.url,
                  method: t?.method,
                });
                // P1-5：store.scanId 为空（无会话 / 测试直呼）视为放行；
                // 非空且不等于本次 scanId（已启动新扫描）则丢弃。
                const cur = useScanStore.getState();
                if (cur.scanId && cur.scanId !== scanId) return;
                setReport(wrapped);
                saveScanToHistory(wrapped);
              } catch {
                // 报告拉取失败：不阻塞收尾，前端仍保有实时日志视图
              }
            })();
          }
          current.close();
        } else if (data.type === 'scan_stopped') {
          setStatus('stopped');
          current.close();
        } else if (data.type === 'scan_paused') {
          // [P0-FIX] 扫描暂停：更新状态但不关闭 SSE（等待恢复）
          setStatus('paused');
        } else if (data.type === 'scan_resumed') {
          setStatus('running');
        } else if (data.type === 'scan_error') {
          // P2-SSE（M9）：命名空间被回收（终态 TTL 后 dispose）时后端推「扫描不存在或已结束」，
          // 已完成的扫描不应显示为错误态 —— 先拉报告对账，仅当报告不可得且仍处 running 时才置 error。
          // 优先用后端携带的 code 判断（SCAN_NOT_FOUND=2001），兼容旧后端无 code 时回退字符串匹配。
          const payload = data.payload as { message?: string; code?: number };
          const isNotFound =
            payload.code === ErrorCode.SCAN_NOT_FOUND ||
            (!payload.code && /不存在|已结束/.test(payload.message ?? ''));
          if (isNotFound) {
            void reconcile().then(() => {
              const cur = useScanStore.getState();
              if (cur.scanId && cur.scanId !== scanId) return;
              if (cur.status === 'running') setStatus('error');
            });
          } else {
            setStatus('error');
          }
          current.close();
        }
      };

      // P1-3：手动接管重连（浏览器默认自动重连无次数上限、无退避控制）。
      // 收到错误即关闭当前连接（阻止浏览器内置重连），指数退避后重开；
      // 连续失败超过 MAX_RETRIES 次 → 置 status=error 并追加提示事件。
      current.onerror = () => {
        if (es !== current) return; // 旧实例的迟到回调（当前连接已被替换/关闭），忽略
        es?.close();
        es = null;
        retryCount += 1;
        if (retryCount > MAX_RETRIES) {
          const cur = useScanStore.getState();
          if (cur.scanId && cur.scanId !== scanId) return; // 会话已切换，不再兜底
          if (cur.status === 'running') {
            setStatus('error');
            addEvent({
              type: 'scan_error',
              scanId,
              ts: new Date().toISOString(),
              payload: {
                message: i18n.t('common.sseReconnectFailed', { max: MAX_RETRIES }),
              },
            } as ScanEvent);
          }
          return;
        }
        const delay = Math.min(1000 * 2 ** (retryCount - 1), 8000); // 1s/2s/4s/8s/8s
        backoffTimer = window.setTimeout(open, delay);
      };
    };

    open();

    return () => {
      disposed = true;
      es?.close();
      if (backoffTimer !== null) {
        window.clearTimeout(backoffTimer);
        backoffTimer = null;
      }
    };
  }, [scanId, addEvent, setStatus, setReport, clearEvents, saveScanToHistory, setWafSuggestion, clearWafSuggestion]);
}
