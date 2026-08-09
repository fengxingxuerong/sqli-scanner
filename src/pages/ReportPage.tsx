import { useEffect, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Container,
  Paper,
  Grid,
  Typography,
  Chip,
  Button,
  Alert,
  IconButton,
  InputAdornment,
  TextField,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Skeleton,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import FileDownloadIcon from '@mui/icons-material/FileDownload';
import ClearIcon from '@mui/icons-material/Clear';
import { useScan } from '../hooks/useScan';
import { useScanStore } from '../store/scanStore';
import VulnList from '../components/VulnList';
import VulnDetail from '../components/VulnDetail';
import DbTree from '../components/DbTree';
import ReportExport from '../components/ReportExport';
import SecondOrderGraph, { type GraphHandle as SecondHandle } from '../components/SecondOrderGraph';
import InjectionTopologyGraph, { type GraphHandle as InjectHandle } from '../components/InjectionTopologyGraph';
import { RISK_LABEL, TECHNIQUE_LABEL } from '../shared/constants';
import type { Vulnerability } from '../shared/types';

// 漏洞是否命中搜索词（按 id/pointId/DBMS/描述/风险/技术/payload 模糊匹配）
function vulnMatches(v: Vulnerability, q: string): boolean {
  if (!q) return true;
  const hay = [
    v.id,
    v.pointId,
    v.dbms ?? '',
    v.description,
    RISK_LABEL[v.riskLevel] ?? v.riskLevel,
    TECHNIQUE_LABEL[v.technique] ?? v.technique,
    (v.payloads || []).join(' '),
  ]
    .join(' ')
    .toLowerCase();
  return hay.includes(q);
}

// 目录锚点区块（与导出 HTML 的 TOC、PDF 栅格化排除规则保持一致）
const TOC_SECTIONS = [
  { id: 'sec-vulns', label: '漏洞列表' },
  { id: 'sec-detail', label: '漏洞详情' },
  { id: 'sec-data', label: '拖库数据' },
  { id: 'sec-export', label: '导出' },
];

// 报告页：漏洞列表 + 详情 + 拖库树 + 导出
export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { getReport } = useScan();
  const { report } = useScanStore();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  // 报告页全局搜索：联动过滤漏洞列表（VulnList）+ 拖库数据树（DbTree）
  const [query, setQuery] = useState('');
  const searchRef = useRef<HTMLInputElement>(null);
  // 快捷键：按 / 聚焦全局搜索框（类 GitHub/Linear；输入框聚焦时不触发）
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      const typing = !!el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable);
      if (e.key === '/' && !typing) {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);
  // 目录当前高亮区块（scrollspy）：默认首项，滚动时由 IntersectionObserver 更新
  const [activeSec, setActiveSec] = useState<string>(TOC_SECTIONS[0].id);
  // 报告内容根 ref：PDF 导出时栅格化此节点（不含顶部工具栏；目录栏/导出区经 data-pdf-exclude 排除）
  const contentRef = useRef<HTMLDivElement>(null);
  // 拓扑图便捷导出入口：持 ref 调子组件 exportImage；按钮在 rp-no-print 工具栏，不进 PDF
  const injectGraphRef = useRef<InjectHandle>(null);
  const secondOrderRef = useRef<SecondHandle>(null);

  useEffect(() => {
    if (id) getReport(id);
  }, [id]);

  // 滚动高亮（scrollspy）：观察四个区块，取最靠上的可见区块设为 active。
  // jsdom/SSR 无 IntersectionObserver 时跳过，避免报错（默认高亮首项即可）。
  useEffect(() => {
    if (typeof IntersectionObserver === 'undefined' || !report) return;
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible.length > 0) {
          setActiveSec((visible[0].target as HTMLElement).id);
        }
      },
      { rootMargin: '-72px 0px -55% 0px', threshold: 0 },
    );
    TOC_SECTIONS.forEach((s) => {
      const el = document.getElementById(s.id);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, [report]);

  const q = query.trim().toLowerCase();
  const filteredVulns = report ? report.vulns.filter((v) => vulnMatches(v, q)) : [];
  const selectedVuln: Vulnerability | null =
    filteredVulns.find((v) => v.id === selectedId) || filteredVulns[0] || null;

  // 拓扑图是否实际渲染（决定顶部便捷导出按钮的可用态）
  const hasInjectionGraph = !!(report?.points && report.points.length > 0);
  const disc = report?.summary?.secondOrderDiscovery;
  const storePoints = (report?.points || []).filter((p) => p.isStorePoint);
  const hasSecondOrderGraph = !!(disc || storePoints.length > 0);

  return (
    <Container maxWidth="lg" className="py-6">
      <Box className="flex items-center justify-between mb-4 rp-no-print">
        <Typography variant="h5" fontWeight={700}>
          检测报告
        </Typography>
        <Box className="flex gap-2">
          <Chip
            label={`风险：${report ? RISK_LABEL[report.riskLevel] : '-'}`}
            color={report?.riskLevel === 'Critical' ? 'error' : 'default'}
          />
          <Button variant="outlined" onClick={() => window.print()}>
            打印报告
          </Button>
          <Button variant="text" onClick={() => navigate('/history')}>
            历史
          </Button>
        </Box>
      </Box>
      {/* 打印时隐藏顶部工具栏（风险标签/打印/历史按钮），让报告内容干净输出 */}
      <Box component="style">{`@media print { .rp-no-print { display: none !important } }`}</Box>

      {/* 报告页全局搜索（不进 PDF）：联动过滤漏洞列表 + 拖库数据树 */}
      <Box className="rp-no-print mb-3">
        <TextField
          size="small"
          fullWidth
          label="搜索漏洞 / 数据库 / 表 / 列 / 值"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') setQuery('');
          }}
          inputRef={searchRef}
          InputProps={{
            endAdornment: query ? (
              <InputAdornment position="end">
                <IconButton
                  aria-label="清除搜索"
                  size="small"
                  edge="end"
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={() => setQuery('')}
                >
                  <ClearIcon fontSize="small" />
                </IconButton>
              </InputAdornment>
            ) : undefined,
          }}
        />
      </Box>

      {/* 拓扑图便捷导出入口（不进 PDF）：图未渲染（无对应数据）时禁用 */}
      <Box className="rp-no-print flex flex-wrap gap-2 mb-3">
        <Button
          size="small"
          variant="outlined"
          startIcon={<FileDownloadIcon />}
          disabled={!hasInjectionGraph}
          onClick={() => injectGraphRef.current?.exportImage('png')}
        >
          导出注入拓扑图 (PNG)
        </Button>
        <Button
          size="small"
          variant="outlined"
          startIcon={<FileDownloadIcon />}
          disabled={!hasSecondOrderGraph}
          onClick={() => secondOrderRef.current?.exportImage('png')}
        >
          导出二阶链路 (PNG)
        </Button>
      </Box>

      {!report && (
        <Box className="space-y-3" aria-busy="true">
          <Skeleton variant="text" width="45%" height={40} />
          <Skeleton variant="rectangular" height={96} />
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Skeleton variant="rectangular" height={300} />
            </Grid>
            <Grid item xs={12} md={8}>
              <Skeleton variant="rectangular" height={300} />
            </Grid>
          </Grid>
          <Skeleton variant="rectangular" height={360} />
        </Box>
      )}

      {report && (
        <div ref={contentRef}>
          {/* WAF 规避标注 + 指纹识别汇总（来自 summary.wafEvasion.tamper / summary.wafDetected） */}
          {(report.summary?.wafEvasion?.tamper?.enabled ||
            (Array.isArray(report.summary?.wafDetected) && report.summary.wafDetected.length > 0)) && (
            <Box className="mb-3" sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              {report.summary.wafEvasion?.tamper?.enabled && (
                <Alert severity="info" variant="outlined">
                  tamper 组合：{report.summary.wafEvasion.tamper.plugins.join(' → ')}（强度：
                  {report.summary.wafEvasion.tamper.intensity}）
                </Alert>
              )}
              {Array.isArray(report.summary.wafDetected) && report.summary.wafDetected.length > 0 && (
                <Alert severity="warning" variant="outlined">
                  识别到 WAF：
                  {report.summary.wafDetected.map((w) => `${w.vendor}(${w.confidence})`).join('、')}
                </Alert>
              )}
            </Box>
          )}

          {/* 安全间隔探测告警（来自 summary.safeProbeAlerts，对标 sqlmap --safe-url 偏离告警；仅展示不阻断，可折叠） */}
          {(report.summary.safeProbeAlerts?.length ?? 0) > 0 && (
            <Accordion className="mb-3" defaultExpanded={false} disableGutters>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box className="flex items-center gap-2">
                  <Chip
                    size="small"
                    color="warning"
                    label={`${report.summary.safeProbeAlerts!.length} 条`}
                  />
                  <Typography fontWeight={600}>安全间隔探测告警</Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Alert severity="warning" variant="outlined">
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    扫描期间安全 URL 偏离基线，说明目标可能被 WAF/IPS 拦截、会话失效或触发限流，
                    当前批次检测结果可能失真，建议复核命中结论。
                  </Typography>
                  <Box component="ul" sx={{ m: 0, pl: 2 }}>
                    {(report.summary.safeProbeAlerts || []).map((a, i) => (
                      <Box component="li" key={`${a.url}-${i}`} sx={{ mb: 1 }}>
                        <Typography variant="body2" fontWeight={600}>{a.url}</Typography>
                        <Typography variant="body2">{a.reason}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          基线 {a.baselineStatus}（{a.baselineLen}B）→ 实际 {a.actualStatus}（{a.actualLen}B）
                          {a.ts ? ` · ${new Date(a.ts).toLocaleString()}` : ''}
                        </Typography>
                      </Box>
                    ))}
                  </Box>
                </Alert>
              </AccordionDetails>
            </Accordion>
          )}

          {/* 二阶自动发现（方向 1）：展示自动发现的触发页与识别到的存储点；来自 summary.secondOrderDiscovery + report.points */}
          {(() => {
            const disc = report.summary?.secondOrderDiscovery;
            const storePoints = (report.points || []).filter((p) => p.isStorePoint);
            const storeKinds: Record<string, number> = {};
            for (const p of storePoints) {
              const k = p.storeKind || 'unknown';
              storeKinds[k] = (storeKinds[k] || 0) + 1;
            }
            if (!disc && storePoints.length === 0) return null;
            return (
              <Box className="mb-3" sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                <Typography variant="subtitle2" fontWeight={700}>二阶自动发现</Typography>
                {disc && (
                  <Alert severity="info" variant="outlined">
                    <Typography variant="body2">
                      触发页自动发现：从 {disc.candidates.length} 个候选链接中确认 {disc.confirmed.length} 个会回显存储内容的触发页。
                    </Typography>
                    {disc.confirmed.length > 0 && (
                      <Box component="ul" sx={{ m: 0, pl: 2, mt: 1 }}>
                        {disc.confirmed.map((u, i) => (
                          <Box component="li" key={`${u}-${i}`}>
                            <Typography variant="body2" sx={{ wordBreak: 'break-all' }}>{u}</Typography>
                          </Box>
                        ))}
                      </Box>
                    )}
                  </Alert>
                )}
                {storePoints.length > 0 && (
                  <Alert severity="info" variant="outlined">
                    已识别存储点 {storePoints.length} 个（
                    {Object.entries(storeKinds).map(([k, n]) => `${k}:${n}`).join('、')}
                    ），将作为二阶存储端发起真实写请求。
                  </Alert>
                )}
                <SecondOrderGraph
                  ref={secondOrderRef}
                  candidates={disc?.candidates || []}
                  confirmed={disc?.confirmed || []}
                  storePoints={storePoints.map((p) => ({ param: p.param, storeKind: p.storeKind }))}
                  height={Math.max(260, 20 + Math.max(storePoints.length, disc?.candidates.length || 0) * 96)}
                />
              </Box>
            );
          })()}

          {/* 全局注入拓扑图（全部注入点分布 + 二阶回显） */}
          {report.points && report.points.length > 0 && (() => {
            const disc = report.summary?.secondOrderDiscovery;
            const storePointsLite = (report.points.filter((p) => p.isStorePoint)).map((p) => ({
              param: p.param,
              storeKind: p.storeKind,
            }));
            return (
              <Box className="mb-3">
                <Typography variant="subtitle2" fontWeight={700}>注入点全景拓扑</Typography>
                <InjectionTopologyGraph
                  ref={injectGraphRef}
                  points={report.points}
                  baseUrl={report.target.baseUrl}
                  secondOrder={disc ? { confirmed: disc.confirmed, storePoints: storePointsLite } : undefined}
                  highlightPointIds={report.vulns.map((v) => v.pointId)}
                  height={Math.max(360, 20 + report.points.length * 56 + (disc?.confirmed.length || 0) * 40)}
                />
              </Box>
            );
          })()}

          {/* 目录锚点侧栏（与导出 HTML 的 TOC 对齐；打印时随顶部工具栏隐藏；PDF 导出时经 data-pdf-exclude 排除）
              吸顶 + 响应式：桌面端换行铺开，移动端横向滚动；scrollspy 高亮当前区块 */}
          <Box
            className="rp-no-print mb-3"
            data-pdf-exclude="true"
            sx={{
              position: 'sticky',
              top: 8,
              zIndex: 2,
              bgcolor: 'background.paper',
              py: 1,
              px: 0.5,
              borderRadius: 1,
              display: 'flex',
              alignItems: 'center',
              gap: 1,
              flexWrap: { xs: 'nowrap', md: 'wrap' },
              boxShadow: { xs: 1, md: 0 },
            }}
          >
            <Typography variant="subtitle2" sx={{ mr: 1, whiteSpace: 'nowrap', flexShrink: 0 }}>目录</Typography>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: { xs: 'nowrap', md: 'wrap' }, overflowX: { xs: 'auto', md: 'visible' } }}>
              {TOC_SECTIONS.map((t) => (
                <Button
                  key={t.id}
                  size="small"
                  variant={activeSec === t.id ? 'contained' : 'outlined'}
                  color={activeSec === t.id ? 'primary' : 'inherit'}
                  component="a"
                  href={`#${t.id}`}
                  aria-current={activeSec === t.id ? 'true' : undefined}
                  sx={{ whiteSpace: 'nowrap', flexShrink: 0 }}
                >
                  {t.label}
                </Button>
              ))}
            </Box>
          </Box>

          <Grid container spacing={2}>
          <Grid item xs={12} md={4}>
            <Paper id="sec-vulns" className="p-3" variant="outlined">
              {q && (
                <Typography variant="caption" color="text.secondary" className="block mb-1">
                  命中 {filteredVulns.length} / {report!.vulns.length} 条漏洞
                </Typography>
              )}
              <VulnList
                vulns={filteredVulns}
                selectedId={selectedVuln?.id || null}
                onSelect={setSelectedId}
                search={query}
              />
            </Paper>
          </Grid>
          <Grid item xs={12} md={8} className="space-y-3">
            <Paper id="sec-detail" className="p-3" variant="outlined">
              <VulnDetail vuln={selectedVuln} />
            </Paper>
            <Paper id="sec-data" className="p-3" variant="outlined">
              <DbTree data={report.data} search={query} />
            </Paper>
            <Paper id="sec-export" className="p-3" variant="outlined" data-pdf-exclude="true">
              <ReportExport contentRef={contentRef} />
            </Paper>
          </Grid>
        </Grid>
        </div>
      )}
    </Container>
  );
}
