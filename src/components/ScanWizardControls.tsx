// ScanWizard 的控制块：标题、扫描强度档位、主操作按钮。
// [D109] 从 ScanWizard.tsx 拆出：ScanWizardInner 曾达 228 行 / 43 圈复杂度，
// 超过存量基线（182 / 37）。这里只做展示与回调，状态仍由 ScanPage / ScanWizard 持有。

import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import {
  Box, Button, IconButton, Stack, ToggleButton, ToggleButtonGroup, Typography,
} from '@mui/material';
import {
  History, PauseCircleOutline, PlayArrow, PlayCircleOutline, Stop,
} from '@mui/icons-material';
import InfoHint from './InfoHint';
import { SCAN_PRESETS, getScanPreset, type ScanPresetId } from '../shared/scanPresets';

export function ScanWizardHeader() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  return (
    <Stack direction="row" justifyContent="space-between" alignItems="center" className="mb-4">
      <Box>
        <Box className="flex items-center">
          <Typography variant="h5" fontWeight={700}>{t('scan.title')}</Typography>
          {/* [D85] 小白引导：标题旁一句话说明整页用法 */}
          <InfoHint text={t('configHints.wizard')} />
        </Box>
        <Typography variant="body2" color="text.secondary">{t('scan.subtitle')}</Typography>
      </Box>
      <IconButton title={t('history.title')} aria-label={t('history.title')} onClick={() => navigate('/history')}>
        <History />
      </IconButton>
    </Stack>
  );
}

interface ScanIntensitySelectorProps {
  activePreset?: ScanPresetId | null;
  running: boolean;
  onApplyPreset?: (id: ScanPresetId) => void;
}

export function ScanIntensitySelector({ activePreset, running, onApplyPreset }: ScanIntensitySelectorProps) {
  const { t } = useTranslation();
  const activeHintKey = activePreset ? getScanPreset(activePreset)?.hintKey : undefined;
  return (
    <Box className="mt-3">
      <Stack direction="row" spacing={0.5} alignItems="center" className="mb-1">
        <Typography variant="caption" className="cyber-tag" color="text.secondary">
          {t('scan.intensity')}
        </Typography>
        <InfoHint text={t('configHints.intensity')} />
      </Stack>
      <ToggleButtonGroup
        exclusive
        size="small"
        value={activePreset ?? ''}
        disabled={running}
        onChange={(_, v) => { if (v && onApplyPreset) onApplyPreset(v as ScanPresetId); }}
        aria-label={t('scan.intensity')}
      >
        {SCAN_PRESETS.map((preset) => (
          <ToggleButton
            key={preset.id}
            value={preset.id}
            sx={{
              px: 2,
              textTransform: 'none',
              fontWeight: 600,
              color: 'text.secondary',
              borderColor: 'var(--cy-line)',
              '&.Mui-selected': {
                color: 'var(--cy-cyan)',
                borderColor: 'var(--cy-line-strong)',
                bgcolor: 'var(--cy-cyan-faint)',
              },
            }}
          >
            {t(preset.labelKey)}
          </ToggleButton>
        ))}
      </ToggleButtonGroup>
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.75 }}>
        {activeHintKey ? t(activeHintKey) : t('scan.intensityHint')}
      </Typography>
    </Box>
  );
}

interface ScanActionButtonsProps {
  running: boolean;
  starting?: boolean;
  status: string;
  onStart: () => void;
  onStop: () => void;
  onPause: () => void;
  onResume: () => void;
}

export function ScanActionButtons({
  running, starting, status, onStart, onStop, onPause, onResume,
}: ScanActionButtonsProps) {
  const { t } = useTranslation();
  return (
    <>
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
    </>
  );
}
