// ValidityBanner —— 结论可信度 Banner（[P0-FIX 2026-09-09] A 项）
//
// 核心语义：「未检出」≠「无漏洞」。引擎守卫（server scanValidityGuard）把实测数字与
// 处置建议写进 report.validity / report.summary.verdict，本组件只消费、不判定：
//   · verdict==='inconclusive'        → warning：结论不可信（被封/不可达/会话失效/目标 5xx）
//   · verdict==='no_vulnerability_detected' 且 0 漏洞 → info：阴性结论可信度正常，仍建议人工复核
//     （绝不允许渲染成「安全/无漏洞」的绿色成功语义）
//   · reliable===true 且有漏洞         → 一条 info（含本次实测总请求数）
// 旧报告（无 verdict 也无 validity）不渲染任何横幅，保持向后兼容。
// ReportPage（经 ReportSummarySection）与 ScanPage 收尾态（ScanResult）共用本组件，
// 避免两页文案/判定漂移。

import { Alert, Box, Chip, Stack, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { ReportModel, ScanValidity } from '../shared/types';

// 守卫状态 → 中文标签 i18n 键（blocked=疑似被 WAF/封禁、unreachable=目标不可达…）
export const VALIDITY_STATUS_LABEL_KEY: Record<ScanValidity['status'], string> = {
  ok: 'report.validity.status.ok',
  blocked: 'report.validity.status.blocked',
  unreachable: 'report.validity.status.unreachable',
  session_expired: 'report.validity.status.session_expired',
  target_error: 'report.validity.status.target_error',
};

export type ValidityMode = 'inconclusive' | 'negative' | 'hit';

/**
 * 从报告中解析可信度展示模式。返回 null = 无可信度信息（旧报告），不渲染。
 * 优先消费 summary.verdict；缺省时按 validity.reliable + 漏洞数推断（兼容仅带
 * validity 的 stopped 快照）。
 */
export function resolveValidityMode(report: ReportModel | null | undefined): ValidityMode | null {
  if (!report) return null;
  const validity = report.validity ?? report.summary?.validity;
  const verdict = report.summary?.verdict;
  if (!validity && !verdict) return null;
  const negative = (report.vulns?.length ?? 0) === 0;
  if (verdict === 'inconclusive') return 'inconclusive';
  if (verdict === 'no_vulnerability_detected') {
    // 引擎语义：有漏洞时 verdict 恒为 no_vulnerability_detected，仅 reliable 才提示 info
    if (negative) return 'negative';
    return validity?.reliable ? 'hit' : null;
  }
  // 无 verdict 字段（老引擎报告）：按 validity 推断
  if (validity) {
    if (negative) return validity.reliable ? 'negative' : 'inconclusive';
    return validity.reliable ? 'hit' : null;
  }
  return null;
}

interface Props {
  report: ReportModel | null | undefined;
  className?: string;
}

export default function ValidityBanner({ report, className }: Props) {
  const { t } = useTranslation();
  const mode = resolveValidityMode(report);
  if (!mode || !report) return null;
  const validity = report.validity ?? report.summary?.validity;

  // ── 结论不可信：warning，正文 = 状态标签 + reason + 未完成点数 + advice ──
  if (mode === 'inconclusive') {
    return (
      <Alert severity="warning" variant="outlined" className={className}
        sx={{ alignItems: 'flex-start' }}
        aria-labelledby="validity-inconclusive-title"
      >
        <Stack direction="row" spacing={1} alignItems="center" className="mb-1" flexWrap="wrap" useFlexGap>
          <Typography id="validity-inconclusive-title" variant="subtitle2" fontWeight={700}>
            {t('report.validity.inconclusiveTitle')}
          </Typography>
          {validity && (
            <Chip size="small" color="warning" variant="outlined" label={t(VALIDITY_STATUS_LABEL_KEY[validity.status])} />
          )}
        </Stack>
        {validity && (
          <Box className="space-y-1">
            <Typography variant="body2">{validity.reason}</Typography>
            <Typography variant="body2">
              {t('report.validity.inconclusivePoints', { count: validity.inconclusivePoints?.length ?? 0 })}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {t('report.validity.advicePrefix')}{validity.advice}
            </Typography>
          </Box>
        )}
      </Alert>
    );
  }

  // ── 阴性结论可信度正常：info（明确不是「安全」，仍建议人工复核）──
  if (mode === 'negative') {
    return (
      <Alert severity="info" variant="outlined" className={className}>
        <Typography variant="body2" fontWeight={600}>{t('report.validity.negativeReliable')}</Typography>
        {validity && (
          <Typography variant="caption" color="text.secondary">{validity.reason}</Typography>
        )}
      </Alert>
    );
  }

  // ── 可信 + 有漏洞：一条 info（含实测总请求数）──
  return (
    <Alert severity="info" variant="outlined" className={className}>
      <Typography variant="body2">
        {t('report.validity.reliableWithVulns', { total: validity?.counts?.total ?? 0 })}
      </Typography>
      {validity?.suggestBackoffMs != null && (
        <Typography variant="caption" color="text.secondary">
          {t('report.validity.suggestBackoff', { ms: validity.suggestBackoffMs })}
        </Typography>
      )}
    </Alert>
  );
}
