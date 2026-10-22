// useTriageForm —— [D125] 人工裁决表单状态/保存（从 TriageControls 抽出守复杂度基线）

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiClient } from '../shared/apiClient';
import type { TriageStatus, Vulnerability } from '../shared/types';

export default function useTriageForm(scanId: string, vuln: Vulnerability, onSaved?: () => void) {
  const { t } = useTranslation();
  const [status, setStatus] = useState<TriageStatus>(vuln.triage?.status ?? 'open');
  const [note, setNote] = useState(vuln.triage?.note ?? '');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    setStatus(vuln.triage?.status ?? 'open');
    setNote(vuln.triage?.note ?? '');
    setError('');
  }, [vuln.id, vuln.triage?.status, vuln.triage?.note]);

  const save = async () => {
    setSaving(true);
    setSaved(false);
    setError('');
    try {
      await apiClient.patch(`/scan/${scanId}/findings/${encodeURIComponent(vuln.id)}/triage`, { status, note });
      setSaved(true);
      onSaved?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : t('triage.error'));
    } finally {
      setSaving(false);
    }
  };

  return { status, setStatus, note, setNote, saving, saved, error, save };
}
