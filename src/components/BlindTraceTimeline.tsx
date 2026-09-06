import { useTranslation } from 'react-i18next';
import {
  Box, Typography, Paper, Chip, Accordion, AccordionSummary, AccordionDetails, Stack,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import type { BlindTrace, BlindSamplePoint } from '../shared/types';

// 单指标卡片
function Metric({ label, value }: { label: string; value: string }) {
  return (
    <Paper variant="outlined" className="px-2 py-1 text-center bg-gray-50">
      <Typography variant="caption" color="text.secondary" display="block">
        {label}
      </Typography>
      <Typography variant="body2" fontWeight={600}>
        {value}
      </Typography>
    </Paper>
  );
}

function fmtMs(ms?: number) {
  return ms == null ? '-' : `${(ms * 1000).toFixed(0)}ms`;
}

// 盲注统计判定时间线：把后端传来的结构化 trace 渲染成可点的证据链卡片
export default function BlindTraceTimeline({ trace }: { trace: BlindTrace }) {
  const { t } = useTranslation();
  const isBool = trace.technique === 'boolean';
  return (
    <Box className="mt-3">
      <Box className="flex items-center gap-2 mb-2">
        <Typography variant="subtitle2" fontWeight={600}>
          {t('blindTrace.title')}
        </Typography>
        <Chip
          label={isBool ? t('technique.boolean') : t('technique.time')}
          size="small"
          color="info"
        />
        <Chip
          label={trace.decision === 'vulnerable' ? t('blindTrace.hit') : t('blindTrace.clean')}
          size="small"
          color={trace.decision === 'vulnerable' ? 'error' : 'success'}
        />
        {trace.adaptive && (
          <Chip label={t('blindTrace.adaptive')} size="small" variant="outlined" />
        )}
      </Box>

      {/* 指标卡片 */}
      <Box className="grid grid-cols-3 gap-2 mb-3">
        {isBool ? (
          <>
            <Metric label={t('blindTrace.baselineNoiseRate')} value={(trace.baselineNoiseRate ?? 0).toFixed(2)} />
            <Metric label={t('blindTrace.minStable')} value={(trace.minStable ?? 0).toFixed(2)} />
            <Metric label={t('blindTrace.pairs')} value={String(trace.pairs?.length ?? 0)} />
          </>
        ) : (
          <>
            <Metric label={t('blindTrace.muBaseline')} value={`${(trace.mu ?? 0).toFixed(2)}s`} />
            <Metric label={t('blindTrace.sigmaBaseline')} value={`${(trace.sigma ?? 0).toFixed(2)}s`} />
            <Metric label={t('blindTrace.threshold')} value={`${(trace.threshold ?? 0).toFixed(2)}s`} />
            <Metric label={t('blindTrace.floor')} value={`${(trace.floor ?? 0).toFixed(2)}s`} />
            <Metric label={t('blindTrace.stableRatio')} value={(trace.stableRatio ?? 0).toFixed(2)} />
          </>
        )}
      </Box>

      {/* 基线采样 */}
      <Typography variant="caption" color="text.secondary">
        {t('blindTrace.baselineSamples', { count: trace.baselineSamples.length })}
      </Typography>
      <Stack direction="row" spacing={1} className="flex-wrap mb-3">
        {trace.baselineSamples.map((s: BlindSamplePoint) => (
          <Chip
            key={s.idx}
            size="small"
            variant="outlined"
            label={isBool ? `#${s.idx} ${s.len}B` : `#${s.idx} ${fmtMs(s.ms)}`}
            title={s.excerpt ? t('blindTrace.responseSnippet', { excerpt: s.excerpt }) : undefined}
          />
        ))}
      </Stack>

      {/* 布尔：真假对时间线（可展开看每次采样 + 真假差异） */}
      {isBool &&
        trace.pairs?.map((p, i) => (
          <Accordion key={i} disableGutters>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="body2">
                {t('blindTrace.trueFalsePair', {
                  index: i + 1,
                  ti: p.ti,
                  fi: p.fi,
                  trueRatio: p.trueRatio.toFixed(2),
                  falseRatio: p.falseRatio.toFixed(2),
                  z: p.z == null ? 'NA' : p.z.toFixed(2),
                  significant: p.significant ? t('blindTrace.significant') : t('blindTrace.notSignificant'),
                })}
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="caption" color="text.secondary">
                {t('blindTrace.trueSamples', { count: p.trueSamples.length })}
              </Typography>
              <Stack direction="row" spacing={1} className="flex-wrap mb-2">
                {p.trueSamples.map((s) => (
                  <Chip
                    key={s.idx}
                    size="small"
                    color={s.likeBaseline ? 'default' : 'warning'}
                    label={`#${s.idx} ${s.len}B ${s.likeBaseline ? t('blindTrace.likeBaseline') : t('blindTrace.deviation')}`}
                    title={s.excerpt ? t('blindTrace.responseSnippet', { excerpt: s.excerpt }) : undefined}
                  />
                ))}
              </Stack>
              <Typography variant="caption" color="text.secondary">
                {t('blindTrace.falseSamples', { count: p.falseSamples.length })}
              </Typography>
              <Stack direction="row" spacing={1} className="flex-wrap mb-2">
                {p.falseSamples.map((s) => (
                  <Chip
                    key={s.idx}
                    size="small"
                    color={s.likeBaseline ? 'warning' : 'success'}
                    label={`#${s.idx} ${s.len}B ${s.likeBaseline ? t('blindTrace.likeBaseline') : t('blindTrace.deviation')}`}
                    title={s.excerpt ? t('blindTrace.responseSnippet', { excerpt: s.excerpt }) : undefined}
                  />
                ))}
              </Stack>
              {/* 逐采样真假差异：审计"到底差在哪" */}
              <Typography variant="caption" color="text.secondary">
                {t('blindTrace.trueFalseDiff', { count: p.diffs?.length ?? 0 })}
              </Typography>
              <Stack spacing={1} className="mt-1">
                {(p.diffs || []).map((d) => (
                  <Box key={d.idx} className="rounded border border-gray-200 p-2 bg-gray-50">
                    <Typography variant="caption" className="font-medium">
                      {t('blindTrace.sampleHeader', {
                        index: d.idx,
                        lenDelta: d.lenDelta >= 0 ? `+${d.lenDelta}` : d.lenDelta,
                        offset: d.firstDiffOffset < 0 ? t('blindTrace.none') : d.firstDiffOffset,
                      })}
                    </Typography>
                    {d.changedSnippet && (
                      <Typography
                        variant="caption"
                        component="pre"
                        className="block mt-1 font-mono text-[11px] whitespace-pre-wrap break-all text-gray-700"
                      >
                        {d.changedSnippet}
                      </Typography>
                    )}
                  </Box>
                ))}
              </Stack>
            </AccordionDetails>
          </Accordion>
        ))}

      {/* 时间：注入采样时间线 */}
      {!isBool &&
        trace.injectSamples?.map((s) => (
          <Box key={s.idx} className="flex items-center gap-2 mb-1">
            <Chip size="small" label={`#${s.idx}`} title={s.excerpt ? t('blindTrace.responseSnippet', { excerpt: s.excerpt }) : undefined} />
            <Typography
              variant="body2"
              className={s.delayed ? 'text-red-600 font-semibold' : 'text-gray-500'}
            >
              {fmtMs(s.ms)} {s.delayed ? t('blindTrace.triggeredDelay') : t('blindTrace.normal')}
            </Typography>
          </Box>
        ))}
    </Box>
  );
}