// 授权与安全护栏分段（productionMode / confirmDestructive / 表单写 / PoC 脱敏）
import type { ChangeEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Box, Typography, Switch, Alert, FormControlLabel } from '@mui/material';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';
import SectionTitle from './SectionTitle';

interface GuardSwitchProps {
  checked: boolean;
  onChange: (e: ChangeEvent<HTMLInputElement>) => void;
  labelKey: string;
  hintKey: string;
  warningKey: string;
  showWarning: boolean;
  severity: 'warning' | 'error';
}

/** 单个「开关 + 说明 + 条件告警」行：四个护栏项共用，避免复制 4 份相同 JSX。 */
function GuardSwitch({ checked, onChange, labelKey, hintKey, warningKey, showWarning, severity }: GuardSwitchProps) {
  const { t } = useTranslation();
  return (
    <>
      <FormControlLabel
        sx={{ display: 'flex', mt: 2 }}
        control={<Switch checked={checked} onChange={onChange} />}
        label={t(`scanConfig.${labelKey}`)}
      />
      <Typography variant="caption" color="text.disabled" className="block mt-1">
        {t(`scanConfig.${hintKey}`)}
      </Typography>
      {showWarning && (
        <Alert severity={severity} variant="outlined" className="my-2">
          {t(`scanConfig.${warningKey}`)}
        </Alert>
      )}
    </>
  );
}

export default function SafetyGuardSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { handleToggle } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <SectionTitle hintKey="safetyGuard">{t('scanConfig.safetyGuardTitle')}</SectionTitle>
      {/* ── 授权与安全护栏 [2026-09-23 UI-REACH] ─────────────────────────────
          引擎默认就把目标当生产系统（defaults.js: productionMode=true），高危池
          （写文件 / RCE / 永久改配置 / DoS）必须 confirmDestructive===true 才投放。
          与 OOB / 二阶同一形态 —— 默认关 + 无入口 = 永远测不到。 */}
      <GuardSwitch
        checked={config.productionMode ?? true}
        onChange={handleToggle('productionMode')}
        labelKey="productionModeLabel"
        hintKey="productionModeHint"
        warningKey="productionModeOffWarning"
        showWarning={config.productionMode === false}
        severity="warning"
      />
      <GuardSwitch
        checked={config.confirmDestructive ?? false}
        onChange={handleToggle('confirmDestructive')}
        labelKey="confirmDestructiveLabel"
        hintKey="confirmDestructiveHint"
        warningKey="confirmDestructiveWarning"
        showWarning={config.confirmDestructive === true}
        severity="error"
      />
      {/* [P1-SAFE 2026-11-02] 表单 POST 写请求确认：默认关闭，开启后会向表单 action 发送真实 POST。 */}
      <GuardSwitch
        checked={config.confirmFormWrites ?? false}
        onChange={handleToggle('confirmFormWrites')}
        labelKey="confirmFormWritesLabel"
        hintKey="confirmFormWritesHint"
        warningKey="confirmFormWritesWarning"
        showWarning={config.confirmFormWrites === true}
        severity="warning"
      />
      {/* [P0-SEC 2026-11-02] 报告 PoC 凭据脱敏：默认开启，避免 Cookie/Authorization 随报告外泄。 */}
      <GuardSwitch
        checked={config.pocRedactAuth ?? true}
        onChange={handleToggle('pocRedactAuth')}
        labelKey="pocRedactAuthLabel"
        hintKey="pocRedactAuthHint"
        warningKey="pocRedactAuthWarning"
        showWarning={config.pocRedactAuth === false}
        severity="warning"
      />
    </Box>
  );
}
