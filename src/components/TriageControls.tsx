// TriageControls —— [D125 2026-10-22] 漏洞人工裁决（交付层标注）
//
// 设计约束：
//   · 只改裁决，不触发重扫、不改 verdict/风险/退出码；
//   · PATCH 走 /api/scan/:id/findings/:findingId/triage，成功后由调用方刷新报告；
//   · 渲染在可点击的漏洞卡片内 ⇒ 根节点必须阻断事件冒泡，否则点输入框会折叠卡片。

import { Alert, Button, MenuItem, Select, Stack, TextField, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import useTriageForm from '../hooks/useTriageForm';
import type { TriageStatus, Vulnerability } from '../shared/types';

const STATUSES: TriageStatus[] = ['open', 'confirmed', 'false_positive', 'accepted_risk'];

export default function TriageControls({
  scanId,
  vuln,
  onChanged,
}: {
  scanId: string;
  vuln: Vulnerability;
  onChanged?: () => void;
}) {
  const { t } = useTranslation();
  const { status, setStatus, note, setNote, saving, saved, error, save } = useTriageForm(scanId, vuln, onChanged);

  return (
    <Stack
      spacing={1}
      className="mt-3"
      onClick={(e) => e.stopPropagation()}
      onKeyDown={(e) => e.stopPropagation()}
    >
      <Typography variant="subtitle2" fontWeight={600}>{t('triage.title')}</Typography>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ sm: 'center' }}>
        <Select
          size="small"
          value={status}
          onChange={(e) => setStatus(e.target.value as TriageStatus)}
          inputProps={{ 'aria-label': t('triage.title') }}
          sx={{ minWidth: 140 }}
        >
          {STATUSES.map((s) => (
            <MenuItem key={s} value={s}>{t(`triage.status.${s}`)}</MenuItem>
          ))}
        </Select>
        <TextField
          size="small"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder={t('triage.notePlaceholder')}
          inputProps={{ maxLength: 2000 }}
          sx={{ flex: 1, minWidth: 220 }}
        />
        <Button variant="contained" size="small" onClick={save} disabled={saving}>
          {saving ? t('triage.saving') : t('triage.save')}
        </Button>
      </Stack>
      <Typography variant="caption" color="text.secondary">{t('triage.hint')}</Typography>
      {saved && <Alert severity="success">{t('triage.saved')}</Alert>}
      {error && <Alert severity="error">{error}</Alert>}
    </Stack>
  );
}
