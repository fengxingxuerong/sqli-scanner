// VulnCard —— [D125] 报告页单条漏洞卡片（从 ReportPage 抽出守复杂度/函数体基线）

import { Box, Card, CardContent, Chip, Stack, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import VulnDetail from './VulnDetail';
import TriageControls from './TriageControls';
import { RISK_COLORS, TECHNIQUE_COLORS } from './ReportSummarySection';
import type { Vulnerability } from '../shared/types';

// 人工裁决色标：确认=绿、误报=灰、接受风险=黄、待确认=默认
const TRIAGE_COLORS: Record<string, 'default' | 'success' | 'warning'> = {
  open: 'default',
  confirmed: 'success',
  false_positive: 'default',
  accepted_risk: 'warning',
};

export default function VulnCard({
  vuln,
  expanded,
  onToggle,
  scanId,
  onTriageChanged,
}: {
  vuln: Vulnerability;
  expanded: boolean;
  onToggle: () => void;
  scanId: string;
  onTriageChanged?: () => void;
}) {
  const { t } = useTranslation();

  return (
    <Card
      variant="outlined"
      className="cursor-pointer"
      sx={{ borderLeft: `4px solid ${RISK_COLORS[vuln.riskLevel] || '#888'}` }}
      onClick={onToggle}
      aria-expanded={expanded}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onToggle();
        }
      }}
    >
      <CardContent className="py-3">
        <Stack direction="row" justifyContent="space-between" alignItems="center">
          <Box>
            <Typography variant="subtitle2" fontWeight={600}>
              {vuln.pointId}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {vuln.description || t('report.techniqueInjection', { technique: vuln.technique })}
            </Typography>
          </Box>
          <Stack direction="row" spacing={1} alignItems="center">
            <Chip
              label={vuln.technique}
              size="small"
              sx={{ backgroundColor: TECHNIQUE_COLORS[vuln.technique] || '#888', color: '#fff' }}
            />
            <Chip
              label={vuln.riskLevel}
              size="small"
              sx={{ backgroundColor: RISK_COLORS[vuln.riskLevel] || '#888', color: '#fff' }}
            />
            {vuln.dbms && <Chip label={vuln.dbms} size="small" variant="outlined" />}
            {vuln.triage && vuln.triage.status !== 'open' && (
              <Chip
                label={t(`triage.status.${vuln.triage.status}`)}
                size="small"
                color={TRIAGE_COLORS[vuln.triage.status] || 'default'}
              />
            )}
          </Stack>
        </Stack>
        {expanded && (
          <Box className="mt-3 pt-3 border-t border-gray-200">
            <VulnDetail vuln={vuln} />
            <TriageControls scanId={scanId} vuln={vuln} onChanged={onTriageChanged} />
          </Box>
        )}
      </CardContent>
    </Card>
  );
}
