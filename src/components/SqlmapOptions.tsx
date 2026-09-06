// SqlmapOptions —— 简化版，统一新视觉风格

import { Box, Typography, Paper, Slider, Switch, TextField, FormControlLabel, FormGroup, Checkbox, Divider, Alert, Stack, MenuItem } from '@mui/material';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { SqlmapConfig, TamperInfo } from '../shared/types';
import { apiClient } from '../shared/apiClient';
import { SQLMAP_TECHNIQUES, SQLMAP_DBMS_OPTIONS, SQLMAP_TAMPER_PRESETS } from '../shared/constants';

export default function SqlmapOptions({
  config,
  onChange,
}: {
  config: SqlmapConfig;
  onChange: (patch: Partial<SqlmapConfig>) => void;
}) {
  const { t } = useTranslation();
  const [tampers, setTampers] = useState<string[]>(SQLMAP_TAMPER_PRESETS);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list: TamperInfo[] = await apiClient.tampers();
        if (!cancelled && Array.isArray(list) && list.length) setTampers(list.map((t) => t.name));
      } catch { /* fallback */ }
    })();
    return () => { cancelled = true; };
  }, []);

  const toggleTech = (letter: string, checked: boolean) => {
    const next = checked ? [...config.techniques, letter] : config.techniques.filter((x) => x !== letter);
    onChange({ techniques: next });
  };

  const toggleTamper = (name: string, checked: boolean) => {
    const next = checked ? [...config.tamper, name] : config.tamper.filter((x) => x !== name);
    onChange({ tamper: next });
  };

  const anyDestructive = config.dump || config.osShell || !!config.fileRead;

  return (
    <Paper variant="outlined" sx={{ p: 2.5, borderRadius: 2 }} className="space-y-3">
      <Alert severity="info" variant="outlined" sx={{ '& .MuiAlert-message': { fontSize: 13 } }}>
        {t('sqlmap.introPre')}<b>sqlmap</b>{t('sqlmap.introPost')}
      </Alert>

      {/* 检测强度 */}
      <Typography variant="subtitle2" fontWeight={600}>{t('sqlmap.detectionIntensity')}</Typography>
      <Stack spacing={2}>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('sqlmap.levelLabel', { level: config.level })}</Typography>
          <Slider size="small" min={1} max={5} step={1} value={config.level}
            aria-label={t('sqlmap.levelLabel', { level: config.level })}
            onChange={(_, v) => onChange({ level: v as number })} marks />
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('sqlmap.riskLabel', { risk: config.risk })}</Typography>
          <Slider size="small" min={1} max={3} step={1} value={config.risk}
            aria-label={t('sqlmap.riskLabel', { risk: config.risk })}
            onChange={(_, v) => onChange({ risk: v as number })} marks />
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('sqlmap.threadsLabel', { threads: config.threads })}</Typography>
          <Slider size="small" min={1} max={10} step={1} value={config.threads}
            aria-label={t('sqlmap.threadsLabel', { threads: config.threads })}
            onChange={(_, v) => onChange({ threads: v as number })} marks />
        </Box>
      </Stack>

      <Divider />

      {/* 目标数据库 */}
      <Typography variant="subtitle2" fontWeight={600}>{t('sqlmap.targetDb')}</Typography>
      <TextField select fullWidth size="small" label={t('sqlmap.dbmsLabel')}
        value={config.dbms ?? ''}
        onChange={(e) => onChange({ dbms: e.target.value || null })}>
        <MenuItem value="">{t('sqlmap.dbmsAuto')}</MenuItem>
        {SQLMAP_DBMS_OPTIONS.map((o) => (
          <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>
        ))}
      </TextField>

      <Divider />

      {/* 请求控制 */}
      <Typography variant="subtitle2" fontWeight={600}>{t('sqlmap.requestControl')}</Typography>
      <Stack spacing={1.5}>
        <TextField size="small" label={t('sqlmap.proxyLabel')} placeholder="http://127.0.0.1:8080"
          value={config.proxy ?? ''}
          onChange={(e) => onChange({ proxy: e.target.value.trim() || null })} />
        <Stack direction="row" spacing={2}>
          <TextField size="small" type="number" label={t('sqlmap.timeoutLabel')} value={config.timeoutMs}
            onChange={(e) => onChange({ timeoutMs: Number(e.target.value) || 0 })} sx={{ flex: 1 }} />
          <TextField size="small" type="number" label={t('sqlmap.retryLabel')} value={config.retry}
            onChange={(e) => onChange({ retry: Math.max(0, Number(e.target.value) || 0) })} sx={{ flex: 1 }} />
        </Stack>
        <FormControlLabel control={<Switch checked={config.randomUA} onChange={(e) => onChange({ randomUA: e.target.checked })} />}
          label={t('sqlmap.randomUALabel')} />
      </Stack>

      <Divider />

      {/* 检测技术 */}
      <Typography variant="subtitle2" fontWeight={600}>{t('sqlmap.techniquesTitle')}</Typography>
      <FormGroup row>
        {SQLMAP_TECHNIQUES.map((tech) => (
          <FormControlLabel key={tech.letter}
            control={<Checkbox size="small" checked={config.techniques.includes(tech.letter)}
              onChange={(e) => toggleTech(tech.letter, e.target.checked)} />}
            label={`${tech.letter} · ${t(`sqlmap.tech.${tech.letter}`)}`} />
        ))}
      </FormGroup>

      <Divider />

      {/* Tamper 脚本 */}
      <Typography variant="subtitle2" fontWeight={600}>{t('sqlmap.tamperTitle')}</Typography>
      <Box sx={{ maxHeight: 120, overflow: 'auto' }}>
        <FormGroup row>
          {tampers.map((name) => (
            <FormControlLabel key={name}
              control={<Checkbox size="small" checked={config.tamper.includes(name)}
                onChange={(e) => toggleTamper(name, e.target.checked)} />}
              label={name} sx={{ '& .MuiTypography-root': { fontSize: 12 } }} />
          ))}
        </FormGroup>
      </Box>

      <Divider />

      {/* 破坏性操作 */}
      <Typography variant="subtitle2" fontWeight={600}>{t('sqlmap.destructiveTitle')}</Typography>
      <Stack spacing={1.5}>
        <Stack direction="row" spacing={2}>
          <FormControlLabel control={<Switch checked={config.dump}
            onChange={(e) => onChange({ dump: e.target.checked })} />} label={t('sqlmap.dumpLabel')} />
          <FormControlLabel control={<Switch checked={config.osShell}
            onChange={(e) => onChange({ osShell: e.target.checked })} />} label={t('sqlmap.osShellLabel')} />
        </Stack>
        <TextField size="small" label={t('sqlmap.fileReadLabel')} placeholder={t('sqlmap.fileReadPlaceholder')}
          value={config.fileRead ?? ''}
          onChange={(e) => onChange({ fileRead: e.target.value.trim() || null })} />
      </Stack>
      {anyDestructive && (
        <Alert severity="error" variant="outlined" sx={{ '& .MuiAlert-message': { fontSize: 13 } }}>
          {t('sqlmap.destructiveWarning')}
        </Alert>
      )}

      <Divider />

      {/* 对标 sqlmap 高级参数 */}
      <Typography variant="subtitle2" fontWeight={600}>{t('sqlmap.advancedParams')}</Typography>
      <Stack spacing={1.5}>
        <Stack direction="row" spacing={2}>
          <TextField size="small" type="number" label="--time-sec" value={config.timeSec ?? ''}
            onChange={(e) => onChange({ timeSec: e.target.value ? Number(e.target.value) : null })}
            sx={{ width: 100 }} inputProps={{ min: 1, max: 60 }} />
          <TextField size="small" type="number" label="--ignore-code" value={config.ignoreCode ?? ''}
            onChange={(e) => onChange({ ignoreCode: e.target.value ? Number(e.target.value) : null })}
            sx={{ width: 100 }} inputProps={{ min: 100, max: 599 }} />
        </Stack>
        <Stack direction="row" spacing={2}>
          <TextField size="small" label="--union-cols" placeholder="1-15" value={config.unionCols ?? ''}
            onChange={(e) => onChange({ unionCols: e.target.value.trim() || null })} sx={{ width: 100 }} />
          <TextField size="small" type="number" label="-v (0-6)" value={config.verbose ?? ''}
            onChange={(e) => onChange({ verbose: e.target.value ? Number(e.target.value) : null })}
            sx={{ width: 80 }} inputProps={{ min: 0, max: 6 }} />
        </Stack>
        <Stack direction="row" spacing={2}>
          <TextField size="small" label="--union-char" inputProps={{ maxLength: 1 }}
            placeholder="NULL/N/A" value={config.unionChar ?? ''}
            onChange={(e) => onChange({ unionChar: e.target.value.trim().slice(0, 1) || null })}
            sx={{ width: 100 }} />
          <TextField size="small" label="--union-from" placeholder="information_schema.tables"
            value={config.unionFrom ?? ''}
            onChange={(e) => onChange({ unionFrom: e.target.value.trim() || null })}
            sx={{ flex: 1 }} />
        </Stack>
        <Stack direction="row" spacing={2}>
          <FormControlLabel control={<Switch checked={config.excludeSysdbs ?? true}
            onChange={(e) => onChange({ excludeSysdbs: e.target.checked })} />} label="--exclude-sysdbs" />
          <FormControlLabel control={<Switch checked={config.flushSession ?? false}
            onChange={(e) => onChange({ flushSession: e.target.checked })} />} label="--flush-session" />
          <FormControlLabel control={<Switch checked={config.freshQueries ?? false}
            onChange={(e) => onChange({ freshQueries: e.target.checked })} />} label="--fresh-queries" />
          <FormControlLabel control={<Switch checked={config.smart ?? false}
            onChange={(e) => onChange({ smart: e.target.checked })} />} label="--smart" />
        </Stack>
        <Stack direction="row" spacing={2}>
          <FormControlLabel control={<Switch checked={config.noCast ?? false}
            onChange={(e) => onChange({ noCast: e.target.checked })} />} label="--no-cast" />
          <FormControlLabel control={<Switch checked={config.hex ?? false}
            onChange={(e) => onChange({ hex: e.target.checked })} />} label="--hex" />
          <FormControlLabel control={<Switch checked={config.noEscape ?? false}
            onChange={(e) => onChange({ noEscape: e.target.checked })} />} label="--no-escape" />
        </Stack>
      </Stack>
    </Paper>
  );
}