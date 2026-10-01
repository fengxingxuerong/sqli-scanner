// ============================================================================
// ScanConfigPanel —— 高级扫描配置面板（2026-09-27 拆分为编排层）
// 原实现是 1055 行的单文件上帝组件：15 个配置分段 + 全部变更处理器内联在一起。
// 现结构：处理器集中在 scanConfig/scanConfigActions.ts，各分段是
// scanConfig/*Section.tsx（props 统一为 config + onChange），本文件只负责
// 折叠头 + 分段编排 —— 分段顺序与分隔线位置和拆分前逐位一致。
// 契约守卫（src/tests/scanConfig.contract.test.ts）改为扫描整个 scanConfig/ 目录，
// 新增分段自动纳入「键接线」检查，守卫强度不变。
// ============================================================================
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Box, Typography, Collapse, IconButton, Divider, Paper } from '@mui/material';
import { ExpandMore, ExpandLess, Settings } from '@mui/icons-material';
import type { ScanConfig, EngineType, WafSuggestion } from '../shared/types';
import DetectionIntensitySection from './scanConfig/DetectionIntensitySection';
import SafetyGuardSection from './scanConfig/SafetyGuardSection';
import InjectionScopeSection from './scanConfig/InjectionScopeSection';
import AdvancedInjectionSection from './scanConfig/AdvancedInjectionSection';
import RequestControlSection from './scanConfig/RequestControlSection';
import DataExtractionSection from './scanConfig/DataExtractionSection';
import EnumerationSection from './scanConfig/EnumerationSection';
import NetworkAuthSection from './scanConfig/NetworkAuthSection';
import ScopeSecuritySection from './scanConfig/ScopeSecuritySection';
import PayloadTuningSection from './scanConfig/PayloadTuningSection';
import WafEvasionSection from './scanConfig/WafEvasionSection';
import CrawlerSection from './scanConfig/CrawlerSection';
import SessionSection from './scanConfig/SessionSection';
import NoSqlSection from './scanConfig/NoSqlSection';
import OobSection from './scanConfig/OobSection';
import SecondOrderSection from './scanConfig/SecondOrderSection';

interface ScanConfigPanelProps {
  config: ScanConfig;
  mode: EngineType;
  onChange: (patch: Partial<ScanConfig>) => void;
  wafSuggestion?: WafSuggestion[];
}

export default function ScanConfigPanel({ config, mode, onChange, wafSuggestion }: ScanConfigPanelProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);

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

          <DetectionIntensitySection config={config} onChange={onChange} />

          <Divider />

          <SafetyGuardSection config={config} onChange={onChange} />

          <Divider />

          <InjectionScopeSection config={config} onChange={onChange} />

          <Divider />

          {/* [2026-10-01 UI-REACH §1.3] 高级注入面：CLI 侧 sqlmap 对标的 7 个注入形态键 */}
          <AdvancedInjectionSection config={config} onChange={onChange} />

          <Divider />

          <RequestControlSection config={config} onChange={onChange} />

          <Divider />

          <DataExtractionSection config={config} onChange={onChange} />

          <Divider />

          <EnumerationSection config={config} onChange={onChange} />

          <Divider />

          <NetworkAuthSection config={config} onChange={onChange} />

          {mode === 'builtin' && (
            <>
              <Divider />
              <ScopeSecuritySection config={config} onChange={onChange} />
            </>
          )}

          {mode === 'builtin' && (
            <>
              <Divider />
              <PayloadTuningSection config={config} onChange={onChange} />
            </>
          )}

          {mode === 'builtin' && (
            <>
              <Divider />
              <WafEvasionSection config={config} onChange={onChange} wafSuggestion={wafSuggestion} />
            </>
          )}

          {mode === 'builtin' && (
            <>
              <Divider />
              <CrawlerSection config={config} onChange={onChange} />
            </>
          )}

          <Divider />

          <SessionSection config={config} onChange={onChange} />

          {mode === 'builtin' && (
            <>
              <Divider />
              <NoSqlSection config={config} onChange={onChange} />
              <Divider />
              <OobSection config={config} onChange={onChange} />
              <Divider />
              <SecondOrderSection config={config} onChange={onChange} />
            </>
          )}

        </Paper>
      </Collapse>
    </Box>
  );
}
