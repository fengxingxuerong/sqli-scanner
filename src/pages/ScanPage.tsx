// ScanPage —— 骨架：组装扫描流程各组件，管理状态

import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import {
  Container, Stack, Box,
} from '@mui/material';
import ScanWizard from '../components/ScanWizard';
import ScanSidebar from '../components/ScanSidebar';
import ScanConfirmDialogs from '../components/ScanConfirmDialogs';
import ScanProgress from '../components/ScanProgress';
import { useScanActivity } from '../hooks/useScanActivity';
import ScanResult from '../components/ScanResult';
import { useScan } from '../hooks/useScan';
import { useEvents } from '../hooks/useEvents';
import { useScanStore } from '../store/scanStore';
import { DEFAULT_CONFIG, DEFAULT_SQLMAP_CONFIG } from '../shared/constants';
import { tauriBridge } from '../shared/tauriBridge';
import { ApiError } from '../shared/apiClient';
import type { MethodType, ScanConfig, SqlmapConfig } from '../shared/types';
import { ErrorCode } from '../shared/types';

// ── 解析 JSON 文本 ──
function parseJson(text: string): Record<string, string> {
  if (!text.trim()) return {};
  return JSON.parse(text);
}

export default function ScanPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { startScan, stopScan, pauseScan, resumeScan } = useScan();

  const scanId = useScanStore((s) => s.scanId);
  const status = useScanStore((s) => s.status);
  const report = useScanStore((s) => s.report);
  const engine = useScanStore((s) => s.engine);
  const setEngine = useScanStore((s) => s.setEngine);
  const setStatus = useScanStore((s) => s.setStatus);
  const wafSuggestion = useScanStore((s) => s.wafSuggestion);
  // H3：不再订阅 events 数组 —— SSE 高峰期整页（含向导表单树）随每个事件重渲染的
  // 问题就此消除。进度展示只消费 store 增量维护的聚合值（H2），仅在点级事件时更新。
  // [D80] progressTotal/processedCount 不再于页面级订阅：进度展示（含 H2 聚合值消费）
  // 已随 ProgressView 整体在 ScanProgress 内，子组件自订阅比重排整页更贴 H3 初衷。
  useEvents(scanId);

  const [url, setUrl] = useState('');
  const [method, setMethod] = useState<MethodType>('GET');
  const [bodyText, setBodyText] = useState('');
  const [cookieText, setCookieText] = useState('');
  const [headerText, setHeaderText] = useState('');
  const [config, setConfig] = useState<ScanConfig>({ ...DEFAULT_CONFIG });
  const [sqlmapConfig, setSqlmapConfig] = useState<SqlmapConfig>({ ...DEFAULT_SQLMAP_CONFIG });
  const [error, setError] = useState('');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [sqlConfirmOpen, setSqlConfirmOpen] = useState(false);
  const [starting, setStarting] = useState(false);

  const running = status === 'running';
  // progressTotal/processedCount 由 ProgressView 自行订阅（H2 聚合值），此处不再中转
  // [D80] pct/progressValue 已随进度条留在 ProgressView（单一真源），此处不再重复计算
  const sqlDestructive = engine === 'sqlmap' && (sqlmapConfig.dump || sqlmapConfig.osShell || !!sqlmapConfig.fileRead);

  const doStart = async (
    bp: Record<string, string>, cp: Record<string, string>, hp: Record<string, string>
  ) => {
    setStarting(true);
    try {
      // [D81] 不能只 invoke start_engine：它会 kill 旧引擎再拉新的（端口/token 都变），
      // 必须用重启后重取的实连信息，否则后续请求全带旧 token（401 → Network Error）。
      await tauriBridge.restartEngineAndApply();
      await startScan({
        engine, url: url.trim(), method,
        bodyParams: bp, cookieParams: cp, headerParams: hp,
        config: { ...config, techniques: config.techniques ?? DEFAULT_CONFIG.techniques },
        sqlmapConfig,
      });
    } catch (e: unknown) {
      // 根据后端错误码区分行为：ENGINE_BUSY / RATE_LIMITED 提示重试，其余展示原始消息
      let msg = t('scan.errors.startFailed');
      if (e instanceof ApiError) {
        if (e.code === ErrorCode.ENGINE_BUSY) {
          msg = t('scan.errors.engineBusy');
        } else if (e.code === ErrorCode.RATE_LIMITED) {
          msg = t('scan.errors.rateLimited');
        } else {
          msg = e.message || t('scan.errors.startFailed');
        }
      } else if (e instanceof Error) {
        msg = e.message || t('scan.errors.startFailed');
      }
      setError(msg);
      setStatus('error');
    } finally {
      setStarting(false);
    }
  };

  const parseForm = (): { bodyParams: Record<string, string>; cookieParams: Record<string, string>; headerParams: Record<string, string> } | null => {
    setError('');
    if (!url.trim()) { setError(t('scan.errors.emptyUrl')); return null; }
    try {
      return {
        bodyParams: parseJson(bodyText),
        cookieParams: parseJson(cookieText),
        headerParams: parseJson(headerText),
      };
    } catch { setError(t('scan.errors.invalidJson')); return null; }
  };

  // H3：回调引用稳定化（配合 ScanWizard 的 React.memo，表单未变时跳过子树 diff）
  const handleDoStart = useCallback(doStart, [engine, method, url, config, sqlmapConfig, startScan, setStatus, t]);
  const handleParseForm = useCallback(parseForm, [url, bodyText, cookieText, headerText, t]);
  const handleStartStable = useCallback(async () => {
    const parsed = handleParseForm();
    if (!parsed) return;
    // 自带引擎拖库 → 二次确认
    if (engine === 'builtin' && config.enableExtract) { setConfirmOpen(true); return; }
    // sqlmap 破坏性操作 → 二次确认
    if (engine === 'sqlmap' && sqlDestructive) { setSqlConfirmOpen(true); return; }
    await handleDoStart(parsed.bodyParams, parsed.cookieParams, parsed.headerParams);
  }, [handleParseForm, engine, config.enableExtract, sqlDestructive, handleDoStart]);

  const handleStop = useCallback(() => { if (scanId) void stopScan(scanId); }, [scanId, stopScan]);
  const handlePause = useCallback(() => { if (scanId) void pauseScan(scanId); }, [scanId, pauseScan]);
  const handleResume = useCallback(() => { if (scanId) void resumeScan(scanId); }, [scanId, resumeScan]);
  const handleErrorClear = useCallback(() => setError(''), []);

  // [D80] 扫描过程全可见：进度区滚入视口 + 全局扫描线（hook 见 useScanActivity）
  const progressRef = useScanActivity(scanId, running);

  const handleConfigChange = useCallback((patch: Partial<ScanConfig>) =>
    setConfig((c) => ({ ...c, ...patch })), []);
  const handleSqlmapConfigChange = useCallback((patch: Partial<SqlmapConfig>) =>
    setSqlmapConfig((c) => ({ ...c, ...patch })), []);

  return (
    <Container maxWidth="lg" className="py-6">
      {/* 双栏：左扫描向导，右授权边界 / CI 退出码信息栏（sticky，宽屏下消除右侧死白） */}
      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: { xs: '1fr', md: '1.9fr 1fr' },
          gap: 3,
          alignItems: 'start',
        }}
      >
        <Box sx={{ minWidth: 0 }}>
          <ScanWizard
            url={url}
            method={method}
            bodyText={bodyText}
            cookieText={cookieText}
            headerText={headerText}
            config={config}
            sqlmapConfig={sqlmapConfig}
            engine={engine}
            running={running}
            starting={starting}
            error={error}
            wafSuggestion={wafSuggestion}
            status={status}
            onUrlChange={setUrl}
            onMethodChange={setMethod}
            onBodyTextChange={setBodyText}
            onCookieTextChange={setCookieText}
            onHeaderTextChange={setHeaderText}
            onConfigChange={handleConfigChange}
            onSqlmapConfigChange={handleSqlmapConfigChange}
            onEngineChange={setEngine}
            onErrorClear={handleErrorClear}
            onStart={handleStartStable}
            onStop={handleStop}
            onPause={handlePause}
            onResume={handleResume}
          />
        </Box>

        <Stack spacing={2} sx={{ position: { md: 'sticky' }, top: { md: 88 } }}>
          <ScanSidebar />
        </Stack>
      </Box>

      {scanId && (
        <ScanProgress ref={progressRef} running={running} />
      )}

      <ScanResult
        report={report}
        status={status}
        navigate={navigate}
      />

      {/* 两类破坏性操作二次确认（D79 拆至 ../components/ScanConfirmDialogs） */}
      <ScanConfirmDialogs
        extractOpen={confirmOpen}
        sqlmapOpen={sqlConfirmOpen}
        onCloseExtract={() => setConfirmOpen(false)}
        onConfirmExtract={() => {
          setConfirmOpen(false);
          const parsed = parseForm();
          if (parsed) void handleDoStart(parsed.bodyParams, parsed.cookieParams, parsed.headerParams);
        }}
        onCloseSqlmap={() => setSqlConfirmOpen(false)}
        onConfirmSqlmap={() => {
          setSqlConfirmOpen(false);
          const parsed = parseForm();
          if (parsed) void handleDoStart(parsed.bodyParams, parsed.cookieParams, parsed.headerParams);
        }}
      />
    </Container>
  );
}
