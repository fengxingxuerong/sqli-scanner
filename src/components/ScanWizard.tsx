// ScanWizard —— 扫描向导：URL 输入 + 开始/停止按钮 + 高级设置 + WAF 建议

import { memo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box, Card, CardContent, Button, TextField, Stack, Typography, Alert,
  Collapse, Divider, InputAdornment,
} from '@mui/material';
import { ExpandMore, ExpandLess } from '@mui/icons-material';
import TargetForm from './TargetForm';
import ScanConfigPanel from './ScanConfigPanel';
import SqlmapOptions from './SqlmapOptions';
import EnginePicker from './EnginePicker';
import { ScanWizardHeader, ScanIntensitySelector, ScanActionButtons } from './ScanWizardControls';
import { tryAutoDetect, looksLikeRawRequest } from '../shared/requestParser';
import type { ScanPresetId } from '../shared/scanPresets';
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
  /** 当前生效的扫描预设档位（受控，null = 未选过任何预设） */
  activePreset?: ScanPresetId | null;
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
  /** 应用扫描预设档位（quick / standard / deep） */
  onApplyPreset?: (id: ScanPresetId) => void;
}

// H3：memo 化 —— ScanPage 在扫描中因 status/report 等变化重渲染时，
// 若表单 props 未变（回调已由父级 useCallback/setter 稳定化），跳过整棵向导子树的 diff。
function ScanWizardInner(props: ScanWizardProps) {
  const { t } = useTranslation();
  const {
    url, method, bodyText, cookieText, headerText, config, sqlmapConfig,
    engine, running, starting, error, wafSuggestion, status, activePreset,
    onUrlChange, onMethodChange, onBodyTextChange, onCookieTextChange, onHeaderTextChange,
    onConfigChange, onSqlmapConfigChange, onEngineChange, onErrorClear,
    onStart, onStop, onPause, onResume, onApplyPreset,
  } = props;

  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [autoHint, setAutoHint] = useState('');

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
      <ScanWizardHeader />

      {error && (
        <Alert severity="error" className="mb-3" onClose={onErrorClear}>{error}</Alert>
      )}

      {/* 主卡片 */}
      <Card variant="outlined" className="cyber-panel cyber-clip cyber-panel--scan" sx={{ borderRadius: 0 }}>
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

          {/* [D107] 扫描强度三档：原本预设 chips 埋在「高级设置」折叠里，
              新用户第一次打开只看到一个 URL 框，不知道该选多重。提到主区后，
              「快 / 标准 / 深」一眼可选，选中档位即时显示它改了什么。 */}
          <ScanIntensitySelector
            activePreset={activePreset}
            running={running}
            onApplyPreset={onApplyPreset}
          />

          {/* 大按钮 + 暂停/续跑 */}
          <ScanActionButtons
            running={running}
            starting={starting}
            status={status}
            onStart={onStart}
            onStop={onStop}
            onPause={onPause}
            onResume={onResume}
          />

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
              {/* [D85] 引擎选择区拆至 ../EnginePicker（含 sqlmap 预检） */}
              <EnginePicker
                engine={engine}
                running={running}
                onEngineChange={onEngineChange}
              />

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
                activePreset={activePreset}
                onApplyPreset={onApplyPreset}
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
