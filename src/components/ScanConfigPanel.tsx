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
import type { ScanConfig, EngineType, WafSuggestion, TechniqueType, ExtractScopeMode, ExtractScopeConfig } from '../shared/types';
import { TECHNIQUES, BUILTIN_DBMS_OPTIONS, EXTRACT_SCOPE_OPTIONS } from '../shared/constants';
import type { ExtractScopeField } from '../shared/constants';
import { parseScopeList } from '../shared/scanConfig';
import WafTamperPanel from './WafTamperPanel';

/** 非 SQL 注入的三类（与后端 ScanManager 的 kinds 白名单严格一致） */
const NO_SQL_KINDS = ['nosql', 'graphql', 'ssti'] as const;

/** 枚举动作的输入项（顺序 = UI 展示顺序）。哪些项与当前动作相关由 EXTRACT_SCOPE_OPTIONS.needs 决定。 */
const SCOPE_FIELDS: { key: ExtractScopeField; label: string }[] = [
  { key: 'dbs', label: 'scanConfig.extractScopeDbs' },
  { key: 'tables', label: 'scanConfig.extractScopeTables' },
  { key: 'cols', label: 'scanConfig.extractScopeCols' },
  { key: 'keyword', label: 'scanConfig.extractScopeKeyword' },
];

/** 该动作会用到哪些输入项 —— 用不到的置灰禁用，避免「填了但选了不看它的动作」这种白填。 */
function scopeFieldsFor(mode: ExtractScopeMode): ExtractScopeField[] {
  return EXTRACT_SCOPE_OPTIONS.find((o) => o.value === mode)?.needs ?? [];
}

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

  // [P0-FIX 2026-09-09] 字符串型配置键统一走这里（matchString / notString / testFilter / testSkip）。
  // 这些键在后端是**字符串**（Detector.matchAnchors 用 text.includes()、payloadRegistry 用子串匹配），
  // 用布尔开关表达 = 勾了但传了错的类型，引擎侧静默按「真页含 'true'」这种荒谬规则跑。
  // 空串 → undefined：关闭态在请求体里干脆地没这个键，而不是发个 '' 让后端去猜。
  const handleText = (key: keyof ScanConfig) => (e: React.ChangeEvent<HTMLInputElement>) => {
    const v = e.target.value.trim();
    onChange({ [key]: v === '' ? undefined : v } as Partial<ScanConfig>);
  };

  // [2026-09-26] matchCode（对标 --code）是**对象**形态 { true, false }（100-599 的期望状态码）。
  // 两侧都空 = 不启用 → 整个键从请求体省略（与其它锚点「关闭态不留空值」同口径）。
  // 只填一侧是合法的（后端 clampInt 逐侧校验，单侧期望同样能当判据）。
  const setMatchCode = (side: 'true' | 'false', raw: string) => {
    const n = Number(String(raw).trim());
    const cur = { ...(config.matchCode ?? {}) } as { true?: number; false?: number };
    if (raw.trim() === '' || !Number.isFinite(n)) delete cur[side];
    else cur[side] = Math.floor(n);
    onChange({ matchCode: Object.keys(cur).length ? cur : undefined });
  };

  // [2026-09-23 E2] 枚举动作的子字段更新：undefined 一律**删键**（而不是留个空值），
  // 与其它配置「关闭态在请求体里干脆地没这个键」口径一致 —— 后端 sanitizeExtractScope
  // 也是按「有值才写入」处理，两侧不会出现「有键无值」的中间态。
  const setScopeField = (key: ExtractScopeField | 'excludeSysdbs', value: unknown) => {
    const cur = config.extractScope;
    if (!cur) return;
    const next = { ...cur } as Record<string, unknown>;
    if (value === undefined) delete next[key];
    else next[key] = value;
    onChange({ extractScope: next as unknown as ExtractScopeConfig });
  };

  // 授权范围：多行/逗号（或分号）分隔 → string[]；留空 = 不启用（发 undefined，后端零行为变化）
  const handleScopeChange = (raw: string) => {
    const list = parseScopeList(raw);
    onChange({ scope: list.length ? list : undefined });
  };

  // [2026-09-23 UI-REACH] 嵌套对象配置（noSql / oob / secondOrder）的子字段更新。
  // 与 setScopeField 同口径：undefined 一律**删键**（关闭态在请求体里干脆地没这个键）。
  // 刻意**不**在此自动打开 enabled —— OOB 会向回调地址发起出站回连、二阶会发出真实写请求，
  // 「填了地址就自动生效」会把两个有副作用的动作变成隐蔽副作用，总开关必须由用户显式打开。
  const patchNested = (key: 'noSql' | 'oob' | 'secondOrder', field: string, value: unknown) => {
    const cur = (config[key] ?? {}) as Record<string, unknown>;
    const next: Record<string, unknown> = { ...cur };
    if (value === undefined) delete next[field];
    else next[field] = value;
    onChange({ [key]: next } as unknown as Partial<ScanConfig>);
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

          {/* ── 授权与安全护栏 [2026-09-23 UI-REACH] ─────────────────────────────
              引擎默认就把目标当生产系统（defaults.js: productionMode=true），高危池
              （写文件 / RCE / 永久改配置 / DoS）必须 confirmDestructive===true 才投放。
              这两键此前没有 UI 入口，后果不是「没有护栏」而是**能力被默认值锁死**：
              界面用户无论怎么调 level/risk 都拿不到高危载荷，报告却只写「未检出」。
              与 OOB / 二阶同一形态 —— 默认关 + 无入口 = 永远测不到。 */}
          <Box>
            <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.safetyGuardTitle')}</Typography>
            <FormControlLabel
              control={<Switch checked={config.productionMode ?? true} onChange={handleToggle('productionMode')} />}
              label={t('scanConfig.productionModeLabel')}
            />
            <Typography variant="caption" color="text.disabled" className="block mt-1">
              {t('scanConfig.productionModeHint')}
            </Typography>
            {config.productionMode === false && (
              <Alert severity="warning" variant="outlined" className="my-2">
                {t('scanConfig.productionModeOffWarning')}
              </Alert>
            )}
            <FormControlLabel
              sx={{ display: 'flex', mt: 2 }}
              control={<Switch checked={config.confirmDestructive ?? false} onChange={handleToggle('confirmDestructive')} />}
              label={t('scanConfig.confirmDestructiveLabel')}
            />
            <Typography variant="caption" color="text.disabled" className="block mt-1">
              {t('scanConfig.confirmDestructiveHint')}
            </Typography>
            {config.confirmDestructive === true && (
              <Alert severity="error" variant="outlined" className="mt-2">
                {t('scanConfig.confirmDestructiveWarning')}
              </Alert>
            )}
          </Box>

          <Divider />

          {/* ── 注入点范围 ── */}
          {/* [2026-09-23] 这两键此前「引擎已消费 / REST 白名单已收 / UI 无入口」：
              能力在，用户拿不到。默认关（与 TargetParser 默认一致）。 */}
          <Box>
            <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.injectionScope')}</Typography>
            <Stack spacing={2}>
              <FormControlLabel
                control={<Switch checked={config.testPath ?? false} onChange={handleToggle('testPath')} />}
                label={t('scanConfig.testPathLabel')}
              />
              <Typography variant="caption" color="text.disabled">
                {t('scanConfig.testPathHint')}
              </Typography>
              <FormControlLabel
                control={<Switch checked={config.testHeaders ?? false} onChange={handleToggle('testHeaders')} />}
                label={t('scanConfig.testHeadersLabel')}
              />
              <Typography variant="caption" color="text.disabled">
                {t('scanConfig.testHeadersHint')}
              </Typography>
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
              {/* [2026-09-23 UI-REACH] delay / maxReq（对标 sqlmap --delay / --max-requests）。
                  delay 与上面的 ratePerSec 是**两套机制**：一个是固定间隔、一个是令牌桶平均速率 ——
                  文案必须说清，否则使用者会以为是重复项。maxReq 是总请求上限（0=不限），
                  靶场与大目标上的安全阀。上限 60 秒与引擎侧 MAX_DELAY_SEC 一致。 */}
              <Box>
                <Typography variant="caption" color="text.secondary">{t('scanConfig.delayLabel')}: {config.delay ?? 0} {t('scanConfig.seconds')}</Typography>
                <Slider
                  value={config.delay ?? 0}
                  min={0} max={60} step={1}
                  aria-label={t('scanConfig.delayLabel')}
                  onChange={handleNumber('delay')}
                  size="small"
                />
                <Typography variant="caption" color="text.disabled">{t('scanConfig.delayHint')}</Typography>
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary">{t('scanConfig.maxReqLabel')}</Typography>
                <input
                  type="number"
                  min={0}
                  className="mt-1 w-full px-3 py-2 border rounded text-sm"
                  aria-label={t('scanConfig.maxReqLabel')}
                  placeholder="0"
                  value={config.maxReq ?? 0}
                  onChange={(e) => {
                    const n = Number(e.target.value);
                    onChange({ maxReq: Number.isFinite(n) && n > 0 ? n : 0 });
                  }}
                />
                <Typography variant="caption" color="text.disabled">{t('scanConfig.maxReqHint')}</Typography>
              </Box>
              {/* [2026-09-23 UI-REACH] timeThresholdMs：登记在 SCAN_CONFIG_KEYS 但面板从未渲染
                  （契约测试当时把「登记」当「有入口」，故这条断链一直假绿）。
                  它是时间盲注的真/假判据阈值 —— 目标链路慢（跨地域/CDN）时 1500ms 会误判，
                  快的时候又过于宽松，属于必须能调的判定参数。 */}
              <Box>
                <Typography variant="caption" color="text.secondary">{t('scanConfig.timeThreshold')}: {config.timeThresholdMs} ms</Typography>
                <Slider
                  value={config.timeThresholdMs}
                  min={100} max={60000} step={100}
                  aria-label={t('scanConfig.timeThreshold')}
                  onChange={handleNumber('timeThresholdMs')}
                  size="small"
                />
                <Typography variant="caption" color="text.disabled">
                  {t('scanConfig.timeThresholdHint')}
                </Typography>
              </Box>
              {/* [2026-09-23 UI-REACH] prefix / suffix：payload 闭合控制（对标 sqlmap --prefix/--suffix）。
                  同样登记在案却无控件的假暴露键。手工确认过注入点上下文、而引擎自动闭合探测
                  失败时，这是唯一的补救手段（后端 clamp 上限 200 字符）。 */}
              <Box>
                <Typography variant="caption" color="text.secondary">{t('scanConfig.payloadClosure')}</Typography>
                <Box className="grid grid-cols-2 gap-2 mt-1">
                  <input
                    className="px-3 py-2 border rounded text-sm"
                    aria-label={t('scanConfig.prefixLabel')}
                    placeholder={t('scanConfig.prefixPlaceholder')}
                    maxLength={200}
                    value={config.prefix ?? ''}
                    onChange={handleText('prefix')}
                  />
                  <input
                    className="px-3 py-2 border rounded text-sm"
                    aria-label={t('scanConfig.suffixLabel')}
                    placeholder={t('scanConfig.suffixPlaceholder')}
                    maxLength={200}
                    value={config.suffix ?? ''}
                    onChange={handleText('suffix')}
                  />
                </Box>
                <Typography variant="caption" color="text.disabled">
                  {t('scanConfig.payloadClosureHint')}
                </Typography>
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

          {/* ── 枚举与拖库 [2026-09-23 E2] ── */}
          {/* 这条链此前断在两处：引擎能跑（engine/extractScope.js）、CLI 能用
              （bin/cli/config.js:314），但 REST 白名单没收该键（传了静默丢弃）、UI 无入口
              → Web / 桌面 / API 三端实际拿不到枚举与拖库能力。 */}
          <Box>
            <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.enumeration')}</Typography>
            <Stack spacing={2}>
              <FormControl size="small" fullWidth>
                <InputLabel>{t('scanConfig.extractScopeLabel')}</InputLabel>
                <Select
                  value={config.extractScope?.mode ?? ''}
                  label={t('scanConfig.extractScopeLabel')}
                  onChange={(e) => {
                    const v = e.target.value as ExtractScopeMode | '';
                    // 留空 = 不启用：整键发 undefined（与其它开关「关闭态干净」口径一致）
                    onChange({ extractScope: v === '' ? undefined : { ...(config.extractScope ?? {}), mode: v } });
                  }}
                >
                  <MenuItem value="">{t('scanConfig.extractScopeNone')}</MenuItem>
                  {EXTRACT_SCOPE_OPTIONS.map((o) => (
                    <MenuItem key={o.value} value={o.value}>{t(`scanConfig.extractScopes.${o.value}`)}</MenuItem>
                  ))}
                </Select>
              </FormControl>

              {config.extractScope && (
                <>
                  <Typography variant="caption" color="text.disabled">
                    {t('scanConfig.extractScopeHint')}
                  </Typography>
                  {SCOPE_FIELDS.map((f) => {
                    const need = scopeFieldsFor(config.extractScope!.mode).includes(f.key);
                    return (
                      <Box key={f.key} sx={{ opacity: need ? 1 : 0.45 }}>
                        <Typography variant="caption" color="text.secondary">{t(f.label)}</Typography>
                        <input
                          className="mt-1 w-full px-3 py-2 border rounded text-sm"
                          aria-label={t(f.label)}
                          disabled={!need}
                          value={(f.key === 'keyword'
                            ? (config.extractScope!.keyword ?? '')
                            : ((config.extractScope![f.key as 'dbs' | 'tables' | 'cols'] ?? []) as string[]).join(', '))}
                          onChange={(e) => {
                            const raw = e.target.value;
                            if (f.key === 'keyword') {
                              setScopeField('keyword', raw.trim() || undefined);
                            } else {
                              const list = parseScopeList(raw);
                              setScopeField(f.key, list.length ? list : undefined);
                            }
                          }}
                        />
                      </Box>
                    );
                  })}
                  <FormControlLabel
                    control={
                      <Switch
                        checked={config.extractScope.excludeSysdbs !== false}
                        onChange={(e) => setScopeField('excludeSysdbs', e.target.checked)}
                      />
                    }
                    label={t('scanConfig.extractScopeExcludeSys')}
                  />
                  <Alert severity="warning" variant="outlined">
                    {t('scanConfig.extractWarning')}
                  </Alert>
                </>
              )}
            </Stack>
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
              {/* ── 授权范围与传输安全（[P0-SEC] scope 硬约束 + insecureTls；仅内置引擎透传）── */}
              <Box>
                <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.scopeSecurity')}</Typography>
                <Stack spacing={2}>
                  <Box>
                    <Typography variant="caption" color="text.secondary">{t('scanConfig.scopeLabel')}</Typography>
                    <textarea
                      className="mt-1 w-full px-3 py-2 border rounded text-sm"
                      style={{ minHeight: 56, resize: 'vertical' }}
                      placeholder={t('scanConfig.scopePlaceholder')}
                      aria-label={t('scanConfig.scopeLabel')}
                      value={(config.scope ?? []).join('\n')}
                      onChange={(e) => handleScopeChange(e.target.value)}
                    />
                    <Typography variant="caption" color="text.disabled">
                      {t('scanConfig.scopeHint')}
                    </Typography>
                  </Box>
                  <FormControlLabel
                    control={<Switch checked={config.insecureTls ?? false} onChange={handleToggle('insecureTls')} />}
                    label={t('scanConfig.insecureTlsLabel')}
                  />
                  {config.insecureTls && (
                    <Alert severity="warning" variant="outlined">
                      {t('scanConfig.insecureTlsWarning')}
                    </Alert>
                  )}
                  <FormControlLabel
                    control={<Switch checked={config.validationSkip !== false} onChange={handleToggle('validationSkip')} />}
                    label={t('scanConfig.validationSkipLabel')}
                  />
                  <Typography variant="caption" color="text.disabled">
                    {t('scanConfig.validationSkipHint')}
                  </Typography>
                </Stack>
              </Box>
            </>
          )}

          {mode === 'builtin' && (
            <>
              <Divider />
              {/* ── payload 与响应判定调优（[P0-FIX 2026-09-09] 后端已支持、UI 补接的开关）──
                  这些键以前在面板上根本不存在（或只写 store 不进 startScan），后果分两种：
                  · 预筛/静态跳过的预算控制勾不到 → 对大目标多发几倍无用请求；
                  · matchString/notString 无入口 → 强动态页面的布尔盲注只能靠相似度比对，误报/漏报无法人工锺定。 */}
              <Box>
                <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.payloadTuning')}</Typography>
                <Stack spacing={2}>
                  <FormControlLabel
                    control={<Switch checked={config.prefilter !== false} onChange={handleToggle('prefilter')} />}
                    label={t('scanConfig.prefilterLabel')}
                  />
                  <Typography variant="caption" color="text.disabled">
                    {t('scanConfig.prefilterHint')}
                  </Typography>
                  <FormControlLabel
                    control={<Switch checked={config.prefilterSinglePoint ?? false} onChange={handleToggle('prefilterSinglePoint')} />}
                    label={t('scanConfig.prefilterSingleLabel')}
                  />
                  <FormControlLabel
                    control={<Switch checked={config.skipStatic ?? false} onChange={handleToggle('skipStatic')} />}
                    label={t('scanConfig.skipStaticLabel')}
                  />

                  <Divider />

                  <FormControlLabel
                    control={<Switch checked={config.useRegistry ?? false} onChange={handleToggle('useRegistry')} />}
                    label={t('scanConfig.useRegistryLabel')}
                  />
                  <Box>
                    <Typography variant="caption" color="text.secondary">{t('scanConfig.testFilterLabel')}</Typography>
                    <input
                      className="mt-1 w-full px-3 py-2 border rounded text-sm"
                      placeholder={t('scanConfig.testFilterPlaceholder')}
                      aria-label={t('scanConfig.testFilterLabel')}
                      value={config.testFilter ?? ''}
                      onChange={handleText('testFilter')}
                    />
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">{t('scanConfig.testSkipLabel')}</Typography>
                    <input
                      className="mt-1 w-full px-3 py-2 border rounded text-sm"
                      placeholder={t('scanConfig.testSkipPlaceholder')}
                      aria-label={t('scanConfig.testSkipLabel')}
                      value={config.testSkip ?? ''}
                      onChange={handleText('testSkip')}
                    />
                  </Box>
                  {!config.useRegistry && (
                    <Alert severity="info" variant="outlined">
                      {t('scanConfig.useRegistryGate')}
                    </Alert>
                  )}

                  <Divider />

                  <FormControl size="small" fullWidth>
                    <InputLabel>{t('scanConfig.dbmsLabel')}</InputLabel>
                    <Select
                      value={config.dbms ?? ''}
                      label={t('scanConfig.dbmsLabel')}
                      onChange={(e) => onChange({ dbms: e.target.value || null })}
                    >
                      <MenuItem value="">{t('scanConfig.dbmsAuto')}</MenuItem>
                      {BUILTIN_DBMS_OPTIONS.map((o) => (
                        <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>
                      ))}
                    </Select>
                    <Typography variant="caption" color="text.disabled">
                      {t('scanConfig.dbmsHint')}
                    </Typography>
                  </FormControl>

                  <Divider />

                  <Box>
                    <Typography variant="caption" color="text.secondary">{t('scanConfig.matchStringLabel')}</Typography>
                    <input
                      className="mt-1 w-full px-3 py-2 border rounded text-sm"
                      placeholder={t('scanConfig.matchStringPlaceholder')}
                      aria-label={t('scanConfig.matchStringLabel')}
                      value={config.matchString ?? ''}
                      onChange={handleText('matchString')}
                    />
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">{t('scanConfig.notStringLabel')}</Typography>
                    <input
                      className="mt-1 w-full px-3 py-2 border rounded text-sm"
                      placeholder={t('scanConfig.notStringPlaceholder')}
                      aria-label={t('scanConfig.notStringLabel')}
                      value={config.notString ?? ''}
                      onChange={handleText('notString')}
                    />
                  </Box>
                  <Typography variant="caption" color="text.disabled">
                    {t('scanConfig.anchorHint')}
                  </Typography>

                  {/* [2026-09-26 UI-REACH] 判定锚点族的其余成员（对标 --titles / --code / --regexp）。
                      引擎 Detector._matchByTitle/_matchByCode/_matchByRegexp 一直在消费、
                      REST 白名单也收，唯独前端没有控件 —— 强动态页面上「真假响应只差状态码」
                      或「只差一个正则片段」时，用户拿不到任何手段告诉引擎判据是什么，
                      于是判不出来就落「未检出」。这是能力缺失，不是便利开关。 */}
                  <Divider />
                  <FormControlLabel
                    control={<Switch checked={config.matchTitle ?? false} onChange={handleToggle('matchTitle')} />}
                    label={t('scanConfig.matchTitleLabel')}
                  />
                  <Box>
                    <Typography variant="caption" color="text.secondary">{t('scanConfig.matchCodeLabel')}</Typography>
                    <Stack direction="row" spacing={1} className="mt-1">
                      <input
                        className="w-full px-3 py-2 border rounded text-sm"
                        type="number"
                        min={100}
                        max={599}
                        placeholder={t('scanConfig.matchCodeTruePlaceholder')}
                        aria-label={t('scanConfig.matchCodeTruePlaceholder')}
                        value={config.matchCode?.true ?? ''}
                        onChange={(e) => setMatchCode('true', e.target.value)}
                      />
                      <input
                        className="w-full px-3 py-2 border rounded text-sm"
                        type="number"
                        min={100}
                        max={599}
                        placeholder={t('scanConfig.matchCodeFalsePlaceholder')}
                        aria-label={t('scanConfig.matchCodeFalsePlaceholder')}
                        value={config.matchCode?.false ?? ''}
                        onChange={(e) => setMatchCode('false', e.target.value)}
                      />
                    </Stack>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">{t('scanConfig.matchRegexpLabel')}</Typography>
                    <input
                      className="mt-1 w-full px-3 py-2 border rounded text-sm"
                      placeholder={t('scanConfig.matchRegexpPlaceholder')}
                      aria-label={t('scanConfig.matchRegexpLabel')}
                      value={config.matchRegexp ?? ''}
                      onChange={handleText('matchRegexp')}
                    />
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">{t('scanConfig.trueRegexpLabel')}</Typography>
                    <input
                      className="mt-1 w-full px-3 py-2 border rounded text-sm"
                      placeholder={t('scanConfig.trueRegexpPlaceholder')}
                      aria-label={t('scanConfig.trueRegexpLabel')}
                      value={config.trueRegexp ?? ''}
                      onChange={handleText('trueRegexp')}
                    />
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">{t('scanConfig.falseRegexpLabel')}</Typography>
                    <input
                      className="mt-1 w-full px-3 py-2 border rounded text-sm"
                      placeholder={t('scanConfig.falseRegexpPlaceholder')}
                      aria-label={t('scanConfig.falseRegexpLabel')}
                      value={config.falseRegexp ?? ''}
                      onChange={handleText('falseRegexp')}
                    />
                  </Box>
                  <Typography variant="caption" color="text.disabled">
                    {t('scanConfig.anchorFamilyHint')}
                  </Typography>
                </Stack>
              </Box>
            </>
          )}

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
                {/* [2026-09-26 UI-REACH] crawlForms（对标 --forms）：引擎 TargetParser._crawlForms
                    一直在读，但前端此前无控件 → 默认 false 意味着**页面表单一个都不测**，
                    而报告只会写「未检出」（少测一整类注入面，不是便利性差异）。
                    关着爬虫时该开关无意义 → 置灰，避免「填了也不生效」的假暴露。 */}
                <Box className="mt-2">
                  <FormControlLabel
                    control={
                      <Switch
                        checked={config.crawlForms ?? false}
                        disabled={(config.crawlDepth ?? 0) <= 0}
                        onChange={handleToggle('crawlForms')}
                      />
                    }
                    label={t('scanConfig.crawlFormsLabel')}
                  />
                  <Typography variant="caption" color="text.disabled" className="block">
                    {t('scanConfig.crawlFormsHint')}
                  </Typography>
                </Box>
              </Box>
            </>
          )}

          <Divider />

          {/* ── 会话持久化 ── */}
          <Box>
            <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.sessionPersistence')}</Typography>
            <Stack spacing={2}>
              <FormControlLabel
                control={<Switch checked={config.sessionDefault ?? false} onChange={handleToggle('sessionDefault')} />}
                label={t('scanConfig.enableResume')}
              />
              {/* [2026-09-23 UI-REACH] sessionFile：显式指定会话文件名（登记在案却无控件的假暴露键）。
                  后端 isSafeSessionPath 只收「工作目录下的文件名」或系统临时目录内路径，
                  绝对路径与 .. 逃逸一律拒绝 —— 提示里要写清，否则用户填绝对路径会拿到 400。 */}
              <Box>
                <Typography variant="caption" color="text.secondary">{t('scanConfig.sessionFileLabel')}</Typography>
                <input
                  className="mt-1 w-full px-3 py-2 border rounded text-sm"
                  aria-label={t('scanConfig.sessionFileLabel')}
                  placeholder="sqli-session.json"
                  value={config.sessionFile ?? ''}
                  onChange={handleText('sessionFile')}
                />
                <Typography variant="caption" color="text.disabled">{t('scanConfig.sessionFileHint')}</Typography>
              </Box>
            </Stack>
          </Box>

          {/* ── 非 SQL 注入（NoSQL / GraphQL / SSTI）[2026-09-23 UI-REACH] ─────────────
              这三类此前「引擎已实现（detectors/NoSqlInjectionDetector.js）、REST 白名单已收
              （scanRoutes.js:530）、类型与 SCAN_CONFIG_KEYS 都登记了」—— 唯独面板从未渲染过控件。
              而契约测试当时的判据是「键是否登记在 SCAN_CONFIG_KEYS」，于是它被判成「已有入口」、
              不在缺口清单里 → 假绿。真实后果：Web / 桌面端用户永远测不到 NoSQL 注入。 */}
          {mode === 'builtin' && (
            <>
              <Divider />
              <Box>
                <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.noSqlTitle')}</Typography>
                <FormControlLabel
                  control={<Switch checked={config.noSql?.enabled ?? false} onChange={(e) => patchNested('noSql', 'enabled', e.target.checked)} />}
                  label={t('scanConfig.noSqlEnable')}
                />
                <Typography variant="caption" color="text.disabled" className="block mt-1">
                  {t('scanConfig.noSqlHint')}
                </Typography>
                {config.noSql?.enabled && (
                  <Stack spacing={0.5} className="mt-2">
                    {NO_SQL_KINDS.map((k) => {
                      // kinds 缺省 = 三类全跑（后端 ScanManager:627 同义兜底），故此处也按全选显示
                      const selected = config.noSql?.kinds ?? [...NO_SQL_KINDS];
                      const checked = selected.includes(k);
                      return (
                        <FormControlLabel
                          key={k}
                          control={
                            <Switch
                              size="small"
                              checked={checked}
                              onChange={() =>
                                patchNested(
                                  'noSql',
                                  'kinds',
                                  checked ? selected.filter((x) => x !== k) : [...selected, k]
                                )
                              }
                            />
                          }
                          label={t(`scanConfig.noSqlKind.${k}`)}
                        />
                      );
                    })}
                    <Typography variant="caption" color="text.disabled">
                      {t('scanConfig.noSqlKindsHint')}
                    </Typography>
                  </Stack>
                )}
              </Box>

              {/* ── 带外通道（OOB）[2026-09-23 UI-REACH] ─────────────
                  enabled 是**总开关**：techniques 里勾了 oob 还不够，接收端必须在此开启才会启动。
                  这条通道在「无回显 + WAF 拦 sleep/报错/union」的场景里是唯一可达的一条
                  （e2e/oob-real-lab 真 PG 16.2 实测），此前 UI 完全拿不到。 */}
              <Divider />
              <Box>
                <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.oobTitle')}</Typography>
                <FormControlLabel
                  control={<Switch checked={config.oob?.enabled ?? false} onChange={(e) => patchNested('oob', 'enabled', e.target.checked)} />}
                  label={t('scanConfig.oobEnable')}
                />
                <Typography variant="caption" color="text.disabled" className="block mt-1">
                  {t('scanConfig.oobHint')}
                </Typography>
                {config.oob?.enabled && (
                  <>
                    <Alert severity="info" variant="outlined" className="my-2">
                      {t('scanConfig.oobWarning')}
                    </Alert>
                    <Stack spacing={2}>
                      <Box>
                        <Typography variant="caption" color="text.secondary">{t('scanConfig.oobCallbackBase')}</Typography>
                        <input
                          className="mt-1 w-full px-3 py-2 border rounded text-sm"
                          aria-label={t('scanConfig.oobCallbackBase')}
                          placeholder="127.0.0.1:8899"
                          value={config.oob?.callbackBase ?? ''}
                          onChange={(e) => patchNested('oob', 'callbackBase', e.target.value.trim() || undefined)}
                        />
                        <Typography variant="caption" color="text.disabled">{t('scanConfig.oobCallbackBaseHint')}</Typography>
                      </Box>
                      <FormControlLabel
                        control={<Switch size="small" checked={config.oob?.dnsOob ?? false} onChange={(e) => patchNested('oob', 'dnsOob', e.target.checked)} />}
                        label={t('scanConfig.oobDnsEnable')}
                      />
                      {config.oob?.dnsOob && (
                        <Box>
                          <Typography variant="caption" color="text.secondary">{t('scanConfig.oobDnsDomain')}</Typography>
                          <input
                            className="mt-1 w-full px-3 py-2 border rounded text-sm"
                            aria-label={t('scanConfig.oobDnsDomain')}
                            placeholder="oob.example.com"
                            value={config.oob?.dnsDomain ?? ''}
                            onChange={(e) => patchNested('oob', 'dnsDomain', e.target.value.trim() || undefined)}
                          />
                          <Typography variant="caption" color="text.disabled">{t('scanConfig.oobDnsHint')}</Typography>
                        </Box>
                      )}
                    </Stack>
                  </>
                )}
              </Box>

              {/* ── 二阶注入 [2026-09-23 UI-REACH] ─────────────
                  开启即代表将对目标发起**真实写请求**，故警示与写确认位（allowWrites）
                  都必须在界面上给出来：生产护栏（productionMode）一开，非幂等请求没有
                  allowWrites 一律不放行 —— 只给 enabled 不给 allowWrites，
                  用户会得到「开了二阶却永远未检出」这种最难查的假阴性。 */}
              <Divider />
              <Box>
                <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.secondOrderTitle')}</Typography>
                <FormControlLabel
                  control={<Switch checked={config.secondOrder?.enabled ?? false} onChange={(e) => patchNested('secondOrder', 'enabled', e.target.checked)} />}
                  label={t('scanConfig.secondOrderEnable')}
                />
                <Typography variant="caption" color="text.disabled" className="block mt-1">
                  {t('scanConfig.secondOrderHint')}
                </Typography>
                {config.secondOrder?.enabled && (
                  <>
                    <Alert severity="warning" variant="outlined" className="my-2">
                      {t('scanConfig.secondOrderWarning')}
                    </Alert>
                    <Stack spacing={2}>
                      <Box>
                        <Typography variant="caption" color="text.secondary">{t('scanConfig.secondOrderTriggerUrls')}</Typography>
                        <textarea
                          className="mt-1 w-full px-3 py-2 border rounded text-sm"
                          rows={2}
                          aria-label={t('scanConfig.secondOrderTriggerUrls')}
                          placeholder="https://target.example.com/profile"
                          value={(config.secondOrder?.triggerUrls ?? []).join('\n')}
                          onChange={(e) => {
                            const list = parseScopeList(e.target.value);
                            patchNested('secondOrder', 'triggerUrls', list.length ? list : undefined);
                          }}
                        />
                        <Typography variant="caption" color="text.disabled">{t('scanConfig.secondOrderTriggerUrlsHint')}</Typography>
                      </Box>
                      <FormControlLabel
                        control={<Switch size="small" checked={config.secondOrder?.allowWrites ?? false} onChange={(e) => patchNested('secondOrder', 'allowWrites', e.target.checked)} />}
                        label={t('scanConfig.secondOrderAllowWrites')}
                      />
                      <Typography variant="caption" color="text.disabled">
                        {t('scanConfig.secondOrderAllowWritesHint')}
                      </Typography>
                      <FormControlLabel
                        control={<Switch size="small" checked={config.secondOrder?.negativeControl ?? true} onChange={(e) => patchNested('secondOrder', 'negativeControl', e.target.checked)} />}
                        label={t('scanConfig.secondOrderNegativeControl')}
                      />
                      <FormControlLabel
                        control={<Switch size="small" checked={config.secondOrder?.oobTrigger ?? false} onChange={(e) => patchNested('secondOrder', 'oobTrigger', e.target.checked)} />}
                        label={t('scanConfig.secondOrderOobTrigger')}
                      />
                      <Typography variant="caption" color="text.disabled">
                        {t('scanConfig.secondOrderOobTriggerHint')}
                      </Typography>
                      {/* [2026-09-23 UI-REACH] 读写分离：读取阶段的请求发往独立 URL。
                          引擎一直在读这三个字段，但此前 CLI/REST/UI 三条路径都到不了它们。
                          secondUrl 与触发页同级风险（会带会话 Cookie 发请求），后端对其
                          单独做 SSRF + 授权范围校验，不通过则回退触发页。 */}
                      <Box>
                        <Typography variant="caption" color="text.secondary">{t('scanConfig.secondOrderSecondUrl')}</Typography>
                        <input
                          className="mt-1 w-full px-3 py-2 border rounded text-sm"
                          aria-label={t('scanConfig.secondOrderSecondUrl')}
                          placeholder={t('scanConfig.secondOrderSecondUrlPlaceholder')}
                          value={config.secondOrder?.secondUrl ?? ''}
                          onChange={(e) => patchNested('secondOrder', 'secondUrl', e.target.value.trim() || undefined)}
                        />
                        <Typography variant="caption" color="text.disabled">
                          {t('scanConfig.secondOrderSecondUrlHint')}
                        </Typography>
                      </Box>
                      <FormControl size="small" fullWidth>
                        <InputLabel>{t('scanConfig.secondOrderSecondMethod')}</InputLabel>
                        <Select
                          value={config.secondOrder?.secondMethod ?? 'GET'}
                          label={t('scanConfig.secondOrderSecondMethod')}
                          onChange={(e) => patchNested('secondOrder', 'secondMethod', e.target.value)}
                        >
                          {['GET', 'POST', 'HEAD'].map((m2) => (
                            <MenuItem key={m2} value={m2}>{m2}</MenuItem>
                          ))}
                        </Select>
                        <Typography variant="caption" color="text.disabled">
                          {t('scanConfig.secondOrderSecondMethodHint')}
                        </Typography>
                      </FormControl>
                    </Stack>
                  </>
                )}
              </Box>
            </>
          )}

        </Paper>
      </Collapse>
    </Box>
  );
}