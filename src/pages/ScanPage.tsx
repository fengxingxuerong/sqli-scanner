// ScanPage —— 骨架：组装扫描流程各组件，管理状态

import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import {
  Container, Paper, LinearProgress, Divider, Chip, Stack, Typography,
  Dialog, DialogTitle, DialogContent, DialogContentText, DialogActions, Button,
} from '@mui/material';
import ScanWizard from '../components/ScanWizard';
import ScanResult from '../components/ScanResult';
import ProgressView from '../components/ProgressView';
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

const STATUS_COLOR: Record<string, 'default' | 'info' | 'success' | 'warning' | 'error'> = {
  pending: 'default', running: 'info', paused: 'warning', completed: 'success', stopped: 'warning', error: 'error',
};

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
  const progressTotal = useScanStore((s) => s.progressTotal);
  // [P1-FIX] 订阅增量数字而非 processedPointIds 对象：对象每事件新引用 → 整页重渲染，
  // 且 Object.keys().length 为 O(n) 扫描；数字订阅只在计数变化时触发一次重渲染。
  const processedCount = useScanStore((s) => s.processedCount);
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
  const total = progressTotal;
  const processed = processedCount;
  const pct = total > 0 ? Math.round((processed / total) * 100) : null;
  const sqlDestructive = engine === 'sqlmap' && (sqlmapConfig.dump || sqlmapConfig.osShell || !!sqlmapConfig.fileRead);

  const doStart = async (
    bp: Record<string, string>, cp: Record<string, string>, hp: Record<string, string>
  ) => {
    setStarting(true);
    try {
      await tauriBridge.startEngine();
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

  const handleConfigChange = useCallback((patch: Partial<ScanConfig>) =>
    setConfig((c) => ({ ...c, ...patch })), []);
  const handleSqlmapConfigChange = useCallback((patch: Partial<SqlmapConfig>) =>
    setSqlmapConfig((c) => ({ ...c, ...patch })), []);

  return (
    <Container maxWidth="md" className="py-6">
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

      {scanId && (
        <Paper variant="outlined" className="mt-4 p-4" sx={{ borderRadius: 3 }}>
          <Stack direction="row" justifyContent="space-between" alignItems="center" className="mb-2">
            <Typography variant="h6" fontWeight={700}>{t('scan.progress')}</Typography>
            <Chip label={t(`status.${status}`)} color={STATUS_COLOR[status]} size="small" />
          </Stack>
          <LinearProgress
            variant={running ? (pct == null ? 'indeterminate' : 'determinate') : 'determinate'}
            value={running ? (pct == null ? undefined : pct) : 100}
            sx={{ height: 8, borderRadius: 4 }}
          />
          {running && pct != null && (
            <Typography variant="caption" color="text.secondary" className="mt-1">
              {t('scan.pointsProcessed', { processed, total, pct })}
            </Typography>
          )}
          <Divider className="my-3" />
          <ProgressView />
        </Paper>
      )}

      <ScanResult
        report={report}
        status={status}
        navigate={navigate}
      />

      {/* 自带引擎拖库二次确认 */}
      <Dialog open={confirmOpen} onClose={() => setConfirmOpen(false)}>
        <DialogTitle>{t('scan.confirmExtract.title')}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t('scan.confirmExtract.body')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmOpen(false)}>{t('scan.confirmExtract.cancel')}</Button>
          <Button variant="contained" color="warning"
            onClick={() => {
              setConfirmOpen(false);
              const parsed = parseForm();
              if (parsed) void handleDoStart(parsed.bodyParams, parsed.cookieParams, parsed.headerParams);
            }}>
            {t('scan.confirmExtract.confirm')}
          </Button>
        </DialogActions>
      </Dialog>

      {/* sqlmap 破坏性操作二次确认 */}
      <Dialog open={sqlConfirmOpen} onClose={() => setSqlConfirmOpen(false)}>
        <DialogTitle>{t('scan.confirmSqlmap.title')}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t('scan.confirmSqlmap.body')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSqlConfirmOpen(false)}>{t('scan.confirmSqlmap.cancel')}</Button>
          <Button variant="contained" color="error"
            onClick={() => {
              setSqlConfirmOpen(false);
              const parsed = parseForm();
              if (parsed) void handleDoStart(parsed.bodyParams, parsed.cookieParams, parsed.headerParams);
            }}>
            {t('scan.confirmSqlmap.confirm')}
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
}
