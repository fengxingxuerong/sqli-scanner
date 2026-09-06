import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Typography,
  Switch,
  Slider,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Collapse,
  IconButton,
  Divider,
  Stack,
  Alert,
  Chip,
  FormControlLabel,
  Paper,
} from '@mui/material';
import { ExpandMore, ExpandLess, Settings } from '@mui/icons-material';
import type { ScanConfig, EngineType, WafSuggestion, TechniqueType } from '../shared/types';
import { TECHNIQUES } from '../shared/constants';
import WafTamperPanel from './WafTamperPanel';

interface ScanConfigPanelProps {
  config: ScanConfig;
  mode: EngineType;
  onChange: (patch: Partial<ScanConfig>) => void;
  wafSuggestion?: WafSuggestion[];
}

export default function ScanConfigPanel({ config, mode, onChange, wafSuggestion }: ScanConfigPanelProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);

  const handleToggle = (key: keyof ScanConfig) => (e: React.ChangeEvent<HTMLInputElement>) => {
    onChange({ [key]: e.target.checked });
  };

  const handleNumber = (key: keyof ScanConfig) => (_: Event, val: number | number[]) => {
    onChange({ [key]: val as number });
  };

  return (
    <Box className="space-y-2">
      <Box
        className="flex items-center gap-2 cursor-pointer select-none py-1"
        onClick={() => setOpen(!open)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setOpen(!open);
          }
        }}
      >
        <Settings fontSize="small" color="action" />
        <Typography variant="subtitle2" color="text.secondary" sx={{ userSelect: 'none' }}>
          {t('scanConfig.advanced')}
        </Typography>
        <IconButton size="small" aria-label={open ? t('common.collapse') : t('common.expand')}>
          {open ? <ExpandLess fontSize="small" /> : <ExpandMore fontSize="small" />}
        </IconButton>
      </Box>

      <Collapse in={open}>
        <Paper variant="outlined" className="p-4 space-y-5">

          {/* ── 检测强度 ── */}
          <Box>
            <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.detectionIntensity')}</Typography>
            <Stack spacing={3}>
              <Box>
                <Typography variant="caption" color="text.secondary" gutterBottom>
                  {t('scanConfig.levelLabel')} (Level): {config.level ?? 1}
                </Typography>
                <Slider
                  value={config.level ?? 1}
                  min={1} max={5} step={1}
                  aria-label={t('scanConfig.levelLabel')}
                  marks={[
                    { value: 1, label: '1' },
                    { value: 2, label: '2' },
                    { value: 3, label: '3' },
                    { value: 4, label: '4' },
                    { value: 5, label: '5' },
                  ]}
                  onChange={handleNumber('level')}
                  size="small"
                />
                <Typography variant="caption" color="text.disabled">
                  {t('scanConfig.levelHint')}
                </Typography>
              </Box>

              <Box>
                <Typography variant="caption" color="text.secondary" gutterBottom>
                  {t('scanConfig.riskLabel')} (Risk): {config.risk ?? 2}
                </Typography>
                <Slider
                  value={config.risk ?? 2}
                  min={1} max={3} step={1}
                  aria-label={t('scanConfig.riskLabel')}
                  marks={[
                    { value: 1, label: t('scanConfig.riskLow') },
                    { value: 2, label: t('scanConfig.riskMid') },
                    { value: 3, label: t('scanConfig.riskHigh') },
                  ]}
                  onChange={handleNumber('risk')}
                  size="small"
                />
                <Typography variant="caption" color="text.disabled">
                  {t('scanConfig.riskHint')}
                </Typography>
              </Box>

              <FormControl size="small" fullWidth>
                <InputLabel>{t('scanConfig.techniques')}</InputLabel>
                <Select
                  multiple
                  value={config.techniques ?? TECHNIQUES}
                  label={t('scanConfig.techniques')}
                  onChange={(e) => onChange({ techniques: e.target.value as TechniqueType[] })}
                  renderValue={(selected) => (
                    <Box className="flex gap-1 flex-wrap">
                      {(selected as string[]).map((tech) => (
                        <Chip key={tech} label={t(`technique.${tech}`)} size="small" />
                      ))}
                    </Box>
                  )}
                >
                  {TECHNIQUES.map((tech) => (
                    <MenuItem key={tech} value={tech}>
                      {t(`technique.${tech}`)}
                    </MenuItem>
                  ))}
                </Select>
                <Typography variant="caption" color="text.disabled">
                  {t('scanConfig.techniquesHint')}
                </Typography>
              </FormControl>
            </Stack>
          </Box>

          <Divider />

          {/* ── 请求控制 ── */}
          <Box>
            <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.requestControl')}</Typography>
            <Stack spacing={3}>
              <Box>
                <Typography variant="caption" color="text.secondary">{t('scanConfig.timeout')}: {config.timeoutMs}</Typography>
                <Slider value={config.timeoutMs} min={1000} max={60000} step={1000} aria-label={t('scanConfig.timeout')} onChange={handleNumber('timeoutMs')} size="small" />
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">{t('scanConfig.concurrency')}: {config.concurrency}</Typography>
                <Slider value={config.concurrency} min={1} max={10} step={1} aria-label={t('scanConfig.concurrency')} marks onChange={handleNumber('concurrency')} size="small" />
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">{t('scanConfig.retry')}: {config.retry}</Typography>
                <Slider value={config.retry} min={0} max={5} step={1} aria-label={t('scanConfig.retry')} marks onChange={handleNumber('retry')} size="small" />
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">{t('scanConfig.ratePerSec')}: {config.ratePerSec}</Typography>
                <Slider value={config.ratePerSec} min={1} max={100} step={1} aria-label={t('scanConfig.ratePerSec')} onChange={handleNumber('ratePerSec')} size="small" />
              </Box>
            </Stack>
          </Box>

          <Divider />

          {/* ── 数据提取 ── */}
          <Box>
            <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.dataExtraction')}</Typography>
            <FormControlLabel
              control={<Switch checked={config.enableExtract} onChange={handleToggle('enableExtract')} />}
              label={t('scanConfig.enableExtract')}
            />
            {config.enableExtract && (
              <Alert severity="warning" variant="outlined" className="mt-2">
                {t('scanConfig.extractWarning')}
              </Alert>
            )}
          </Box>

          <Divider />

          {/* ── 网络与认证（proxy / basic / cookie / headers）── */}
          <Box>
            <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.networkAuth')}</Typography>
            <Stack spacing={2}>
              <Box>
                <Typography variant="caption" color="text.secondary">{t('scanConfig.proxyLabel')}</Typography>
                <input
                  className="mt-1 w-full px-3 py-2 border rounded text-sm"
                  placeholder={t('scanConfig.proxyPlaceholder')}
                  aria-label={t('scanConfig.proxyLabel')}
                  value={config.proxy ?? ''}
                  onChange={(e) => onChange({ proxy: e.target.value.trim() || null })}
                />
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">{t('scanConfig.basicAuthLabel')}</Typography>
                <input
                  className="mt-1 w-full px-3 py-2 border rounded text-sm"
                  placeholder={t('scanConfig.basicAuthPlaceholder')}
                  aria-label={t('scanConfig.basicAuthLabel')}
                  value={
                    config.auth?.basic
                      ? `${config.auth.basic.username}:${config.auth.basic.password ?? ''}`
                      : ''
                  }
                  onChange={(e) => {
                    const v = e.target.value;
                    if (!v.trim()) {
                      const next = { ...(config.auth ?? {}) } as Record<string, unknown>;
                      delete next.basic;
                      onChange({ auth: Object.keys(next).length ? (next as typeof config.auth) : null });
                      return;
                    }
                    const idx = v.indexOf(':');
                    const username = idx >= 0 ? v.slice(0, idx) : v;
                    const password = idx >= 0 ? v.slice(idx + 1) : '';
                    onChange({ auth: { ...(config.auth ?? {}), basic: { username, password } } });
                  }}
                />
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">{t('scanConfig.cookieLabel')}</Typography>
                <input
                  className="mt-1 w-full px-3 py-2 border rounded text-sm"
                  placeholder={t('scanConfig.cookiePlaceholder')}
                  aria-label={t('scanConfig.cookieLabel')}
                  value={config.auth?.cookie ?? ''}
                  onChange={(e) => {
                    const v = e.target.value;
                    if (!v.trim()) {
                      const next = { ...(config.auth ?? {}) } as Record<string, unknown>;
                      delete next.cookie;
                      onChange({ auth: Object.keys(next).length ? (next as typeof config.auth) : null });
                      return;
                    }
                    onChange({ auth: { ...(config.auth ?? {}), cookie: v } });
                  }}
                />
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">{t('scanConfig.headersLabel')}</Typography>
                <input
                  className="mt-1 w-full px-3 py-2 border rounded text-sm"
                  placeholder={t('scanConfig.headersPlaceholder')}
                  aria-label={t('scanConfig.headersLabel')}
                  value={Object.entries(config.auth?.headers ?? {}).map(([k, v]) => `${k}:${v}`).join(' | ')}
                  onChange={(e) => {
                    const v = e.target.value;
                    const headers: Record<string, string> = {};
                    for (const pair of v.split('|')) {
                      const idx = pair.indexOf(':');
                      if (idx > 0) {
                        const k = pair.slice(0, idx).trim();
                        const hv = pair.slice(idx + 1).trim();
                        if (k) headers[k] = hv;
                      }
                    }
                    if (!Object.keys(headers).length) {
                      const next = { ...(config.auth ?? {}) } as Record<string, unknown>;
                      delete next.headers;
                      onChange({ auth: Object.keys(next).length ? (next as typeof config.auth) : null });
                      return;
                    }
                    onChange({ auth: { ...(config.auth ?? {}), headers } });
                  }}
                />
              </Box>
            </Stack>
          </Box>

          {mode === 'builtin' && (
            <>
              <Divider />
              <Box>
                <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.wafEvasion')}</Typography>
                <WafTamperPanel
                  value={config.wafEvasion?.tamper ?? { enabled: false, plugins: [], intensity: 'medium' }}
                  onChange={(t) => onChange({ wafEvasion: { ...config.wafEvasion, tamper: t } })}
                  suggestion={wafSuggestion}
                />
              </Box>
            </>
          )}

          {mode === 'builtin' && (
            <>
              <Divider />
              <Box>
                <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.crawler')}</Typography>
                <FormControlLabel
                  control={<Switch checked={(config.crawlDepth ?? 0) > 0} onChange={(e) => onChange({ crawlDepth: e.target.checked ? 2 : 0 })} />}
                  label={t('scanConfig.enableCrawler')}
                />
                {(config.crawlDepth ?? 0) > 0 && (
                  <Box className="mt-2">
                    <Typography variant="caption" color="text.secondary">{t('scanConfig.crawlDepth')}: {config.crawlDepth}</Typography>
                    <Slider value={config.crawlDepth ?? 2} min={1} max={3} step={1} aria-label={t('scanConfig.crawlDepth')} marks onChange={handleNumber('crawlDepth')} size="small" />
                  </Box>
                )}
              </Box>
            </>
          )}

          <Divider />

          {/* ── 会话持久化 ── */}
          <Box>
            <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.sessionPersistence')}</Typography>
            <FormControlLabel
              control={<Switch checked={config.sessionDefault ?? false} onChange={handleToggle('sessionDefault')} />}
              label={t('scanConfig.enableResume')}
            />
          </Box>

        </Paper>
      </Collapse>
    </Box>
  );
}