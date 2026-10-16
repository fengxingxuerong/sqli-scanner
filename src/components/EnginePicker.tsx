// EnginePicker —— 引擎选择区（D85 自 ScanWizard 拆出）
// 搬移内容：自带 / sqlmap 两个 Chip + 小白引导 InfoHint + sqlmap 可用性预检
// （原 ScanWizard 的 sqlmapStatus state 与预检 effect 一并搬入，组件自包含）。
// 拆移动机：ScanWizardInner 函数体超复杂度基线（203 > 197），引擎区是自成一体的
// 状态 + 副作用块，拆出后两者都回到基线内；渲染结构与拆分前逐字一致。

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Chip, Stack, Typography } from '@mui/material';
import { sqlmapClient } from '../shared/apiClient';
import InfoHint from './InfoHint';
import type { EngineType } from '../shared/types';

interface EnginePickerProps {
  engine: EngineType;
  running: boolean;
  onEngineChange: (e: EngineType) => void;
}

export default function EnginePicker({ engine, running, onEngineChange }: EnginePickerProps) {
  const { t } = useTranslation();
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

  return (
    <>
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <Typography variant="subtitle2" color="text.secondary">{t('scan.engine')}</Typography>
        {/* [D85] 小白引导：两种引擎怎么选，一句话讲清 */}
        <InfoHint rich title={t('scan.engine')} text={t('configHints.enginePick')} />
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
    </>
  );
}
