import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Typography,
  FormControlLabel,
  Switch,
  FormControl,
  FormGroup,
  Checkbox,
  RadioGroup,
  Radio,
  Chip,
  IconButton,
  Alert,
  Stack,
  CircularProgress,
  Divider,
} from '@mui/material';
import ArrowUpwardIcon from '@mui/icons-material/ArrowUpward';
import ArrowDownwardIcon from '@mui/icons-material/ArrowDownward';
import AutoFixHighIcon from '@mui/icons-material/AutoFixHigh';
import type { TamperConfig, TamperInfo, WafSuggestion } from '../shared/types';
import { TAMPER_INTENSITY_PRESETS } from '../shared/constants';
import { apiClient } from '../shared/apiClient';

interface Props {
  value: TamperConfig;
  onChange: (t: TamperConfig) => void;
  suggestion?: WafSuggestion[];
}

const INTENSITIES: Array<'low' | 'medium' | 'high'> = ['low', 'medium', 'high'];

// tamper 多选 / 强度 / 顺序 / 总开关面板（受控）。
// 清单来自 GET /api/tampers（TamperRegistry.list() 单一事实源，非硬编码）。
// 默认全关、全不选；勾选/强度/顺序均写入 value.plugins（顺序即链式顺序）。
export default function WafTamperPanel({ value, onChange, suggestion }: Props) {
  const { t } = useTranslation();
  const [infos, setInfos] = useState<TamperInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');

  // 拉取 tamper 清单（单一事实源）
  useEffect(() => {
    let alive = true;
    setLoading(true);
    apiClient
      .tampers()
      .then((list) => {
        if (alive) {
          setInfos(list || []);
          setLoadError('');
        }
      })
      .catch((e) => {
        if (alive) setLoadError(e?.message || t('wafTamper.loadFailed'));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [t]);

  const plugins = value.plugins || [];
  const enabled = !!value.enabled;

  const update = (patch: Partial<TamperConfig>) => onChange({ ...value, ...patch });

  // 勾选/取消某个 tamper（维持有序）
  const togglePlugin = (name: string, checked: boolean) => {
    if (checked) {
      if (!plugins.includes(name)) update({ plugins: [...plugins, name] });
    } else {
      update({ plugins: plugins.filter((p) => p !== name) });
    }
  };

  // 上移 / 下移调整链式顺序
  const move = (idx: number, dir: -1 | 1) => {
    const j = idx + dir;
    if (j < 0 || j >= plugins.length) return;
    const next = [...plugins];
    [next[idx], next[j]] = [next[j], next[idx]];
    update({ plugins: next });
  };

  const removeAt = (idx: number) => update({ plugins: plugins.filter((_, i) => i !== idx) });

  // 选择强度档：按预设包填充 plugins（用户可在此之上微调）
  const applyIntensity = (intensity: 'low' | 'medium' | 'high') => {
    update({ intensity, plugins: [...TAMPER_INTENSITY_PRESETS[intensity]] });
  };

  // 一键应用 WAF 推荐：仅写 plugins，不开启 enabled（仅推荐，不自动套用）
  const applySuggestion = (s: WafSuggestion) => {
    update({ plugins: [...s.plugins] });
  };

  const hasSuggestion = Array.isArray(suggestion) && suggestion.length > 0;

  return (
    <Box className="space-y-2">
      {/* 总开关 */}
      <FormControlLabel
        control={<Switch checked={enabled} onChange={(e) => update({ enabled: e.target.checked })} />}
        label={t('wafTamper.enableLabel')}
      />

      {/* 强度三档 */}
      <Box>
        <Typography variant="caption" color="text.secondary">
          {t('wafTamper.intensityTitle')}
        </Typography>
        <RadioGroup
          row
          value={value.intensity}
          onChange={(e) => applyIntensity(e.target.value as 'low' | 'medium' | 'high')}
        >
          {INTENSITIES.map((it) => (
            <FormControlLabel
              key={it}
              value={it}
              control={<Radio size="small" />}
              label={t(`wafTamper.intensity.${it}`)}
            />
          ))}
        </RadioGroup>
      </Box>

      {/* 已选有序组合（顺序 = 链式顺序）+ 上移/下移/删除 */}
      <Box>
        <Typography variant="caption" color="text.secondary">
          {t('wafTamper.selectedTitle')}
        </Typography>
        {plugins.length === 0 ? (
          <Typography variant="body2" color="text.secondary">
            {t('wafTamper.noSelection')}
          </Typography>
        ) : (
          <Stack spacing={0.5} className="mt-1">
            {plugins.map((name, idx) => (
              <Stack key={`${name}-${idx}`} direction="row" spacing={0.5} alignItems="center">
                <IconButton
                  size="small"
                  disabled={idx === 0}
                  onClick={() => move(idx, -1)}
                  aria-label={t('wafTamper.moveUp')}
                >
                  <ArrowUpwardIcon fontSize="small" />
                </IconButton>
                <IconButton
                  size="small"
                  disabled={idx === plugins.length - 1}
                  onClick={() => move(idx, 1)}
                  aria-label={t('wafTamper.moveDown')}
                >
                  <ArrowDownwardIcon fontSize="small" />
                </IconButton>
                <Chip
                  label={`${idx + 1}. ${name}`}
                  onDelete={() => removeAt(idx)}
                  size="small"
                  variant={enabled ? 'filled' : 'outlined'}
                />
              </Stack>
            ))}
          </Stack>
        )}
      </Box>

      {/* 总开关关但已选：提示需启用 */}
      {!enabled && plugins.length > 0 && (
        <Alert severity="warning" variant="outlined">
          {t('wafTamper.notEnabledWarning')}
        </Alert>
      )}

      <Divider className="my-1" />

      {/* 多选清单（来自 /api/tampers，非硬编码） */}
      <Typography variant="caption" color="text.secondary">
        {t('wafTamper.listLabel')}（{loading ? t('wafTamper.loading') : t('wafTamper.listCount', { count: infos.length })}）
      </Typography>
      {loading && <CircularProgress size={18} />}
      {loadError && (
        <Alert severity="error" variant="outlined" className="mt-1">
          {loadError}
        </Alert>
      )}
      {!loading && !loadError && (
        <FormControl component="fieldset" className="mt-1" sx={{ maxHeight: 240, overflow: 'auto', width: '100%' }}>
          <FormGroup>
            {infos.map((info) => (
              <FormControlLabel
                key={info.name}
                control={
                  <Checkbox
                    size="small"
                    checked={plugins.includes(info.name)}
                    onChange={(e) => togglePlugin(info.name, e.target.checked)}
                  />
                }
                label={
                  <span>
                    <b>{info.name}</b> — {info.description}
                  </span>
                }
              />
            ))}
          </FormGroup>
        </FormControl>
      )}

      {/* WAF 识别推荐区（仅推荐，不自动套用） */}
      {hasSuggestion && (
        <Box className="mt-2">
          <Typography variant="caption" color="text.secondary">
            {t('wafTamper.suggestionTitle')}
          </Typography>
          <Stack spacing={1} className="mt-1">
            {suggestion!.map((s) => (
              <Alert
                key={s.vendor}
                severity="info"
                variant="outlined"
                action={
                  <IconButton
                    color="primary"
                    size="small"
                    onClick={() => applySuggestion(s)}
                    aria-label={t('wafTamper.applyFor', { vendor: s.vendor })}
                  >
                    <AutoFixHighIcon fontSize="small" />
                  </IconButton>
                }
              >
                <b>{s.vendor}</b>{t('wafTamper.suggestionColon')}{s.plugins.join(' + ')}
              </Alert>
            ))}
          </Stack>
        </Box>
      )}
    </Box>
  );
}
