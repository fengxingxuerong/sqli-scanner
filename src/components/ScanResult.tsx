// ScanResult —— 扫描结果摘要卡片

import { useTranslation } from 'react-i18next';
import { Card, CardContent, Button, Stack, Typography, Chip } from '@mui/material';
import type { NavigateFunction } from 'react-router-dom';
import type { ReportModel } from '../shared/types';

const RISK_COLOR: Record<string, 'error' | 'warning' | 'info' | 'success'> = {
  Critical: 'error', High: 'warning', Medium: 'info', Low: 'success',
};

interface ScanResultProps {
  report: ReportModel | null;
  status: string;
  navigate: NavigateFunction;
}

export default function ScanResult({ report, status, navigate }: ScanResultProps) {
  const { t } = useTranslation();
  if (!report || !(status === 'completed' || status === 'stopped')) return null;

  const riskKey = (report.riskLevel || '').toLowerCase();

  return (
    <Card
      variant="outlined" className="mt-4"
      sx={{
        borderRadius: 3,
        borderColor: `${RISK_COLOR[report.riskLevel] ?? 'info'}.main`,
      }}
    >
      <CardContent>
        <Stack
          direction={{ xs: 'column', sm: 'row' }}
          justifyContent="space-between"
          alignItems={{ xs: 'flex-start', sm: 'center' }}
          spacing={1.5}
        >
          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
            <Typography variant="h6" fontWeight={700}>
              {status === 'completed' ? t('scanResult.completed') : t('scanResult.stopped')}
            </Typography>
            <Chip
              label={t('scanResult.risk', { level: t(`risk.${riskKey}`) })}
              color={RISK_COLOR[report.riskLevel]}
              size="small"
            />
            <Chip
              label={report.engine === 'sqlmap' ? t('scanResult.engineSqlmap') : t('scanResult.engineBuiltin')}
              variant="outlined" size="small"
            />
          </Stack>
          <Button
            variant="contained"
            onClick={() => navigate(`/report/${report.scanId}`)}
            sx={{ px: 3, borderRadius: 2 }}
          >
            {t('scanResult.viewReport')}
          </Button>
        </Stack>
        <Typography variant="body2" color="text.secondary" className="mt-2">
          {report.engine === 'sqlmap'
            ? t('scanResult.sqlmapStatus', {
                status: report.sqlmap?.status ?? '-',
                vulns: report.sqlmap?.vulns.length ?? 0,
                logs: report.sqlmap?.logs.length ?? 0,
              })
            : t('scanResult.builtinStatus', {
                vulns: report.vulns.length,
                points: report.points.length,
              })}
        </Typography>
      </CardContent>
    </Card>
  );
}