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
  const isBool = trace.technique === 'boolean';
  return (
    <Box className="mt-3">
      <Box className="flex items-center gap-2 mb-2">
        <Typography variant="subtitle2" fontWeight={600}>
          判定时间线
        </Typography>
        <Chip
          label={isBool ? '布尔盲注' : '时间盲注'}
          size="small"
          color="info"
        />
        <Chip
          label={trace.decision === 'vulnerable' ? '命中' : '判干净'}
          size="small"
          color={trace.decision === 'vulnerable' ? 'error' : 'success'}
        />
        {trace.adaptive && (
          <Chip label="自适应门槛" size="small" variant="outlined" />
        )}
      </Box>

      {/* 指标卡片 */}
      <Box className="grid grid-cols-3 gap-2 mb-3">
        {isBool ? (
          <>
            <Metric label="基线噪声率" value={(trace.baselineNoiseRate ?? 0).toFixed(2)} />
            <Metric label="一致率门槛" value={(trace.minStable ?? 0).toFixed(2)} />
            <Metric label="配对对数" value={String(trace.pairs?.length ?? 0)} />
          </>
        ) : (
          <>
            <Metric label="μ 基线均值" value={`${(trace.mu ?? 0).toFixed(2)}s`} />
            <Metric label="σ 基线标准差" value={`${(trace.sigma ?? 0).toFixed(2)}s`} />
            <Metric label="阈值" value={`${(trace.threshold ?? 0).toFixed(2)}s`} />
            <Metric label="自适应下限" value={`${(trace.floor ?? 0).toFixed(2)}s`} />
            <Metric label="稳定率" value={(trace.stableRatio ?? 0).toFixed(2)} />
          </>
        )}
      </Box>

      {/* 基线采样 */}
      <Typography variant="caption" color="text.secondary">
        基线采样（{trace.baselineSamples.length} 次）
      </Typography>
      <Stack direction="row" spacing={1} className="flex-wrap mb-3">
        {trace.baselineSamples.map((s: BlindSamplePoint) => (
          <Chip
            key={s.idx}
            size="small"
            variant="outlined"
            label={isBool ? `#${s.idx} ${s.len}B` : `#${s.idx} ${fmtMs(s.ms)}`}
            title={s.excerpt ? `响应片段：${s.excerpt}` : undefined}
          />
        ))}
      </Stack>

      {/* 布尔：真假对时间线（可展开看每次采样 + 真假差异） */}
      {isBool &&
        trace.pairs?.map((p, i) => (
          <Accordion key={i} disableGutters>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="body2">
                真假对 #{i + 1}（t{p.ti}/f{p.fi}） · 真≈基线 {p.trueRatio.toFixed(2)} ·
                假≠基线 {p.falseRatio.toFixed(2)} · z=
                {p.z == null ? 'NA' : p.z.toFixed(2)}{' '}
                {p.significant ? '✓显著' : '✗不显著'}
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="caption" color="text.secondary">
                真条件样本（{p.trueSamples.length}）
              </Typography>
              <Stack direction="row" spacing={1} className="flex-wrap mb-2">
                {p.trueSamples.map((s) => (
                  <Chip
                    key={s.idx}
                    size="small"
                    color={s.likeBaseline ? 'default' : 'warning'}
                    label={`#${s.idx} ${s.len}B ${s.likeBaseline ? '≈基线' : '偏离'}`}
                    title={s.excerpt ? `响应片段：${s.excerpt}` : undefined}
                  />
                ))}
              </Stack>
              <Typography variant="caption" color="text.secondary">
                假条件样本（{p.falseSamples.length}）
              </Typography>
              <Stack direction="row" spacing={1} className="flex-wrap mb-2">
                {p.falseSamples.map((s) => (
                  <Chip
                    key={s.idx}
                    size="small"
                    color={s.likeBaseline ? 'warning' : 'success'}
                    label={`#${s.idx} ${s.len}B ${s.likeBaseline ? '≈基线' : '偏离'}`}
                    title={s.excerpt ? `响应片段：${s.excerpt}` : undefined}
                  />
                ))}
              </Stack>
              {/* 逐采样真假差异：审计"到底差在哪" */}
              <Typography variant="caption" color="text.secondary">
                真假差异（{p.diffs?.length ?? 0} 次采样）
              </Typography>
              <Stack spacing={1} className="mt-1">
                {(p.diffs || []).map((d) => (
                  <Box key={d.idx} className="rounded border border-gray-200 p-2 bg-gray-50">
                    <Typography variant="caption" className="font-medium">
                      采样 #{d.idx} · Δlen={d.lenDelta >= 0 ? `+${d.lenDelta}` : d.lenDelta} ·
                      首个差异@{d.firstDiffOffset < 0 ? '无' : d.firstDiffOffset}
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
            <Chip size="small" label={`#${s.idx}`} title={s.excerpt ? `响应片段：${s.excerpt}` : undefined} />
            <Typography
              variant="body2"
              className={s.delayed ? 'text-red-600 font-semibold' : 'text-gray-500'}
            >
              {fmtMs(s.ms)} {s.delayed ? '⏱ 触发延迟' : '正常'}
            </Typography>
          </Box>
        ))}
    </Box>
  );
}
