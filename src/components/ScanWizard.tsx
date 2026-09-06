// ScanWizard —— 扫描向导：URL 输入 + 开始/停止按钮 + 高级设置 + WAF 建议

import { memo, useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import {
  Box, Card, CardContent, Button, TextField, Stack, Typography, Alert,
  Collapse, IconButton, Divider, Chip, InputAdornment,
} from '@mui/material';
import { ExpandMore, ExpandLess, PlayArrow, Stop, History, PauseCircleOutline, PlayCircleOutline } from '@mui/icons-material';
import TargetForm from './TargetForm';
import ScanConfigPanel from './ScanConfigPanel';
import SqlmapOptions from './SqlmapOptions';
import { sqlmapClient } from '../shared/apiClient';
import { tryAutoDetect, looksLikeRawRequest } from '../shared/requestParser';
import type { MethodType, ScanConfig, SqlmapConfig, WafDetectedPayload, EngineType } from '../shared/types';

// ── Props ──
interface ScanWizardProps {
  url: string;
  method: MethodType;
  bodyText: string;
  cookieText: string;
  headerText: string;
  config: ScanConfig;
  sqlmapConfig: SqlmapConfig;
  engine: EngineType;
  running: boolean;
  starting?: boolean;
  error: string;
  wafSuggestion: WafDetectedPayload | null;
  status: string;
  onUrlChange: (v: string) => void;
  onMethodChange: (m: MethodType) => void;
  onBodyTextChange: (v: string) => void;
  onCookieTextChange: (v: string) => void;
  onHeaderTextChange: (v: string) => void;
  onConfigChange: (patch: Partial<ScanConfig>) => void;
  onSqlmapConfigChange: (patch: Partial<SqlmapConfig>) => void;
  onEngineChange: (e: EngineType) => void;
  onErrorClear: () => void;
  onStart: () => void;
  onStop: () => void;
  onPause: () => void;
  onResume: () => void;
}

// H3：memo 化 —— ScanPage 在扫描中因 status/report 等变化重渲染时，
// 若表单 props 未变（回调已由父级 useCallback/setter 稳定化），跳过整棵向导子树的 diff。
function ScanWizardInner(props: ScanWizardProps) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const {
    url, method, bodyText, cookieText, headerText, config, sqlmapConfig,
    engine, running, starting, error, wafSuggestion, status,
    onUrlChange, onMethodChange, onBodyTextChange, onCookieTextChange, onHeaderTextChange,
    onConfigChange, onSqlmapConfigChange, onEngineChange, onErrorClear,
    onStart, onStop, onPause, onResume,
  } = props;

  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [autoHint, setAutoHint] = useState('');
  const [sqlmapStatus, setSqlmapStatus] = useState<{ available: boolean } | null>(null);

  // sqlmap 预检
  useEffect(() => {
    if (engine !== 'sqlmap') { setSqlmapStatus(null); return; }
    let cancelled = false;
    sqlmapClient.status()
      .then((s) => { if (!cancelled) setSqlmapStatus(s); })
      .catch(() => { if (!cancelled) setSqlmapStatus({ available: false }); });
    return () => { cancelled = true; };
  }, [engine]);

  const handleUrlChange = (v: string) => {
    onUrlChange(v);
    const d = tryAutoDetect(v);
    if (d) {
      // [P2-FIX] 仅当规范化 URL 与输入不同才二次回填（原实现无条件二次 onUrlChange，
      // 同一 keystroke 双重 setState；v 已是完整 URL 时 d.url 通常等于 v）
      if (d.url !== v) onUrlChange(d.url);
      onMethodChange(d.method);
      if (d.cookieText) onCookieTextChange(d.cookieText);
      if (d.headerText) onHeaderTextChange(d.headerText);
      if (d.bodyText) onBodyTextChange(d.bodyText);
      setAutoHint(t('scan.autoDetected', { method: d.method, url: d.url }));
    } else if (looksLikeRawRequest(v)) {
      setAutoHint(t('scan.autoDetectFailed'));
    } else {
      setAutoHint(''); // 普通输入：清空残留的自动识别提示
    }
  };

  const applyWafSuggestion = () => {
    if (!wafSuggestion || !wafSuggestion.suggestions.length) return;
    const recommended = wafSuggestion.suggestions[0].plugins;
    onConfigChange({
      wafEvasion: {
        ...config.wafEvasion,
        tamper: { ...config.wafEvasion.tamper, plugins: [...recommended] },
      },
    });
  };

  return (
    <>
      {/* 标题 */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" className="mb-4">
        <Box>
          <Typography variant="h5" fontWeight={700}>{t('scan.title')}</Typography>
          <Typography variant="body2" color="text.secondary">{t('scan.subtitle')}</Typography>
        </Box>
        <IconButton title={t('history.title')} aria-label={t('history.title')} onClick={() => navigate('/history')}>
          <History />
        </IconButton>
      </Stack>

      {error && (
        <Alert severity="error" className="mb-3" onClose={onErrorClear}>{error}</Alert>
      )}

      {/* 主卡片 */}
      <Card variant="outlined" sx={{ borderRadius: 3 }}>
        <CardContent sx={{ p: { xs: 2.5, md: 4 } }}>
          <TextField
            fullWidth
            label={t('scan.urlLabel')}
            placeholder={t('scan.urlPlaceholder')}
            value={url}
            onChange={(e) => handleUrlChange(e.target.value)}
            disabled={running}
            helperText={t('scan.urlHelper')}
            InputProps={{ startAdornment: <InputAdornment position="start">🔗</InputAdornment> }}
          />

          {autoHint && (
            <Alert severity="info" variant="outlined" className="mt-2" onClose={() => setAutoHint('')}>
              {autoHint}
            </Alert>
          )}

          {/* 大按钮 */}
          <Button
            fullWidth size="large" variant="contained"
            disabled={starting && !running}
            startIcon={running ? <Stop /> : <PlayArrow />}
            onClick={running ? onStop : onStart}
            sx={{
              mt: 2.5, py: 1.8, borderRadius: 2.5, fontSize: '1.1rem', fontWeight: 700, letterSpacing: '0.02em',
              color: '#fff',
              background: running
                ? 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)'
                : 'linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)',
              boxShadow: running
                ? '0 12px 28px -10px rgba(220, 38, 38, 0.55)'
                : '0 12px 28px -10px rgba(124, 58, 237, 0.55)',
              transition: 'transform 0.18s ease, box-shadow 0.18s ease',
              '&:hover': {
                transform: 'translateY(-2px)',
                boxShadow: running
                  ? '0 16px 32px -10px rgba(220, 38, 38, 0.65)'
                  : '0 16px 32px -10px rgba(124, 58, 237, 0.7)',
              },
            }}
          >
            {running ? t('scan.stopBtn') : starting ? t('scan.starting') : t('scan.startBtn')}
          </Button>

          {/* [P0-FIX] 暂停/续跑：运行中显示「暂停」，暂停中显示「恢复」（对标 sqlmap Ctrl+C 暂停语义） */}
          {running && onPause && (
            <Button
              fullWidth size="large" variant="outlined" color="warning"
              startIcon={<PauseCircleOutline />}
              onClick={onPause}
              sx={{ mt: 1.2, py: 1.4, borderRadius: 2.5, fontSize: '1rem', fontWeight: 600 }}
            >
              {t('scan.pauseBtn')}
            </Button>
          )}
          {status === 'paused' && onResume && (
            <Button
              fullWidth size="large" variant="outlined" color="success"
              startIcon={<PlayCircleOutline />}
              onClick={onResume}
              sx={{ mt: 1.2, py: 1.4, borderRadius: 2.5, fontSize: '1rem', fontWeight: 600 }}
            >
              {t('scan.resumeBtn')}
            </Button>
          )}

          <Stack direction="row" justifyContent="space-between" alignItems="center" className="mt-2">
            <Button size="small" onClick={() => setAdvancedOpen(!advancedOpen)}
              endIcon={advancedOpen ? <ExpandLess /> : <ExpandMore />}>
              {t('scan.advanced')}
            </Button>
            <Typography variant="caption" color="text.secondary">{t('scan.advancedHint')}</Typography>
          </Stack>

          <Collapse in={advancedOpen}>
            <Box className="pt-2 space-y-4">
              <Divider />
              <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                <Typography variant="subtitle2" color="text.secondary">{t('scan.engine')}</Typography>
                <Chip label={t('scan.engineBuiltin')} size="small"
                  color={engine === 'builtin' ? 'primary' : 'default'}
                  variant={engine === 'builtin' ? 'filled' : 'outlined'}
                  onClick={() => !running && onEngineChange('builtin')} />
                <Chip label={t('scan.engineSqlmap')} size="small"
                  color={engine === 'sqlmap' ? 'secondary' : 'default'}
                  variant={engine === 'sqlmap' ? 'filled' : 'outlined'}
                  onClick={() => !running && onEngineChange('sqlmap')} />
              </Stack>

              {engine === 'sqlmap' && sqlmapStatus?.available === false && (
                <Alert severity="warning" variant="outlined">
                  {t('scan.sqlmapUnavailable')}
                </Alert>
              )}

              <TargetForm
                url={url} method={method} bodyText={bodyText}
                cookieText={cookieText} headerText={headerText}
                onChange={(p) => {
                  const keys = Object.keys(p);
                  // 仅 URL 单独变化（用户手动输入）→ 触发粘贴自动识别；
                  // 请求文件导入等多字段 patch → 直接整体填充，不再自动识别
                  if (p.url !== undefined && keys.length === 1) {
                    handleUrlChange(p.url);
                  } else {
                    if (p.url !== undefined) onUrlChange(p.url);
                    if (p.method !== undefined) onMethodChange(p.method);
                    if (p.bodyText !== undefined) onBodyTextChange(p.bodyText);
                    if (p.cookieText !== undefined) onCookieTextChange(p.cookieText);
                    if (p.headerText !== undefined) onHeaderTextChange(p.headerText);
                    setAutoHint('');
                  }
                }}
              />

              <ScanConfigPanel
                config={config} mode={engine}
                onChange={(patch) => onConfigChange(patch)}
                wafSuggestion={wafSuggestion?.suggestions}
              />

              {engine === 'sqlmap' && (
                <SqlmapOptions config={sqlmapConfig} onChange={(patch) => onSqlmapConfigChange(patch)} />
              )}
            </Box>
          </Collapse>
        </CardContent>
      </Card>

      {/* WAF 建议 */}
      {wafSuggestion && wafSuggestion.vendors.length > 0 && (
        <Alert severity="info" variant="outlined" className="mt-3"
          action={<Button color="primary" size="small" onClick={applyWafSuggestion}>{t('waf.applySuggestion')}</Button>}>
          {t('waf.detected', { vendors: wafSuggestion.vendors.map((v) => v.vendor).join('、') })}
          {'，'}
          {t('waf.suggestedTamper', { plugins: wafSuggestion.suggestions[0]?.plugins.join(' + ') || '—' })}
          {'（'}
          {t('waf.applyHint')}
          {'）。'}
        </Alert>
      )}
    </>
  );
}

const ScanWizard = memo(ScanWizardInner);
export default ScanWizard;
