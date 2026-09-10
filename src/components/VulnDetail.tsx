import { useState } from 'react';
import { Box, Typography, Paper, Chip, Alert, Button, Collapse, IconButton } from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckIcon from '@mui/icons-material/Check';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import { useTranslation } from 'react-i18next';
import type { Vulnerability, Target, InjectionPoint, VulnPoc } from '../shared/types';
import { useScanStore } from '../store/scanStore';
import i18n from '../i18n';
import PayloadViewer from './PayloadViewer';
import BlindTraceTimeline from './BlindTraceTimeline';
import { copyText } from './progress/progressUtils';

// 复现请求证据（方法 + URL + 关键头 + 注入 payload），供详情页展示与人工复现
export interface RequestEvidence {
  method: string; // 请求方法（GET/POST/…）
  url: string; // 完整目标 URL
  location: string; // 注入点定位，如 'body.id'
  originalValue: string; // 注入点原始值（剥离 `*` 后）
  headers: Array<[string, string]>; // 关键请求头（含合并后的 Cookie）
  payload: string; // 首条注入 payload
}

// 由漏洞 + 目标/注入点上下文构建可复现的请求报文摘要。
// target 缺失时返回 null（前端兜底：不渲染请求报文区，其余字段照常展示）。
export function buildRequestEvidence(
  vuln: Vulnerability,
  target: Target | null | undefined,
  point: InjectionPoint | null | undefined
): RequestEvidence | null {
  if (!target) return null;

  // 合并目标级 Header 与认证面板自定义 Header（后者优先）；Cookie 由 cookieParams 或 auth.cookie 拼接
  const merged: Record<string, string> = {
    ...(target.headerParams || {}),
    ...(target.config?.auth?.headers || {}),
  };
  const cookiePairs = Object.entries(target.cookieParams || {});
  const cookie =
    cookiePairs.length > 0
      ? cookiePairs.map(([k, v]) => `${k}=${v}`).join('; ')
      : target.config?.auth?.cookie || '';
  if (cookie) merged['Cookie'] = cookie;

  const headers: Array<[string, string]> = Object.entries(merged);

  return {
    method: target.method || 'GET',
    url: target.baseUrl,
    location: point ? `${point.location}.${point.param}` : vuln.pointId,
    originalValue: point?.originalValue ?? '',
    headers,
    payload: vuln.payloads?.[0] ?? '',
  };
}

// 将请求证据格式化为可复制的纯文本报文行
export function formatRequestEvidence(ev: RequestEvidence): string[] {
  const lines: string[] = [];
  // [P0-FIX] 构造更完整的 HTTP 请求报文格式（方法 + URL + HTTP 版本 + Host 头 + 请求头 + 空行 + payload）
  const url = (() => { try { return new URL(ev.url); } catch { return null; } })();
  const path = url ? `${url.pathname}${url.search}` : ev.url;
  lines.push(`${ev.method} ${path} HTTP/1.1`);
  if (url) lines.push(`Host: ${url.host}`);
  for (const [k, v] of ev.headers) {
    if (k.toLowerCase() === 'host') continue; // Host 已单独输出
    lines.push(`${k}: ${v}`);
  }
  lines.push('');
  if (ev.payload) {
    lines.push(i18n.t('vulnDetail.payloadLine', { payload: ev.payload }));
  }
  // 注入点信息作为注释行（人工复现时参考）
  lines.push(`# ${i18n.t('vulnDetail.injectionPointField', { location: ev.location })}${ev.originalValue ? i18n.t('vulnDetail.originalValueSuffix', { value: ev.originalValue }) : ''}`);
  return lines;
}

// ── 复现方式（PoC）区 ──────────────────────────────────────────────
// 单行可复制框：左侧等宽文本 + 右侧复制按钮（复制成功短暂打勾反馈）。
// 导出报告的 poc.curl 就是给工程师粘终端用的，复制必须一键直达。
function CopyBox({ text, ariaLabel }: { text: string; ariaLabel: string }) {
  // 不接 useTranslation：本块只有复制按钮与等宽文本，无可翻译文案（避免无用 hook 与 lint 告警）
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    try {
      await copyText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* 剪贴板不可用（非安全上下文）：静默，用户仍可手动选中复制 */
    }
  };
  return (
    <Box className="flex items-center gap-1">
      <Box
        component="pre"
        sx={{
          flex: 1, m: 0, p: 1, backgroundColor: '#f5f5f5', borderRadius: 1,
          fontSize: '0.72rem', fontFamily: '"JetBrains Mono", monospace',
          whiteSpace: 'pre-wrap', wordBreak: 'break-all',
        }}
      >
        {text}
      </Box>
      <IconButton size="small" onClick={handleCopy} aria-label={ariaLabel}>
        {copied ? <CheckIcon fontSize="small" color="success" /> : <ContentCopyIcon fontSize="small" />}
      </IconButton>
    </Box>
  );
}

// 复现方式（PoC）折叠区：curl 一行 + 可展开的原始报文。
// vuln.poc 缺失（UI 侧报告未经导出路径生成）时整块不渲染，绝不显示空白/undefined。
function PocSection({ poc }: { poc: VulnPoc }) {
  const { t } = useTranslation();
  const [rawOpen, setRawOpen] = useState(false);
  return (
    <Paper variant="outlined" className="p-3 bg-gray-50" data-testid="poc-section">
      <Typography variant="subtitle2" fontWeight={600} className="mb-1">
        {t('vulnDetail.pocTitle')}
      </Typography>
      {poc.curl ? (
        <Box className="mb-1">
          <Typography variant="caption" color="text.secondary">{t('vulnDetail.pocCurl')}</Typography>
          <CopyBox text={poc.curl} ariaLabel={t('vulnDetail.copyCurl')} />
        </Box>
      ) : null}
      {poc.raw ? (
        <Box>
          <Button
            size="small"
            onClick={() => setRawOpen((o) => !o)}
            startIcon={<ExpandMoreIcon sx={{ transform: rawOpen ? 'rotate(180deg)' : 'none', transition: 'transform .2s' }} />}
          >
            {t('vulnDetail.pocRaw')}
          </Button>
          <Collapse in={rawOpen}>
            <Box
              component="pre"
              sx={{
                m: 0, p: 1, backgroundColor: '#1e1e1e', color: '#e0e0e0', borderRadius: 1,
                fontSize: '0.72rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 320, overflowY: 'auto',
              }}
            >
              {poc.raw}
            </Box>
          </Collapse>
        </Box>
      ) : null}
      {(poc.note || poc.generatedAt) && (
        <Typography variant="caption" color="text.secondary" className="mt-1">
          {poc.note ? `${poc.note} · ` : ''}
          {poc.generatedAt ? t('vulnDetail.pocGenerated', { time: poc.generatedAt }) : ''}
        </Typography>
      )}
    </Paper>
  );
}

// 单漏洞详情 + 证据 + 复现请求报文 + Payload 展示
export default function VulnDetail({
  vuln,
  target,
  point,
}: {
  vuln: Vulnerability | null;
  target?: Target | null;
  point?: InjectionPoint | null;
}) {
  // 优先用显式传入的上下文（测试/复用场景）；否则回退到 store 中已加载的报告（ReportPage 场景）
  const report = useScanStore((s) => s.report);
  const { t } = useTranslation();

  if (!vuln) {
    return (
      <Typography variant="body2" color="text.secondary">
        {t('vulnDetail.selectPrompt')}
      </Typography>
    );
  }

  const ctxTarget = target ?? report?.target ?? null;
  const ctxPoint = point ?? report?.points?.find((p) => p.id === vuln.pointId) ?? null;
  const request = buildRequestEvidence(vuln, ctxTarget, ctxPoint);

  return (
    <Box className="space-y-3">
      <Box className="flex items-center gap-2">
        <Chip label={t(`risk.${vuln.riskLevel.toLowerCase()}`)} color="error" size="small" />
        <Typography variant="h6">{t(`technique.${vuln.technique}`)}</Typography>
      </Box>
      <Paper variant="outlined" className="p-3 bg-gray-50">
        <Typography variant="body2">
          <b>{t('vulnDetail.injectionPointLabel')}</b>
          {vuln.pointId}
        </Typography>
        <Typography variant="body2">
          <b>{t('vulnDetail.dbmsLabel')}</b>
          {vuln.dbms || t('vulnDetail.unknownDbms')}
        </Typography>
        <Typography variant="body2">
          <b>{t('vulnDetail.descLabel')}</b>
          {vuln.description || '-'}
        </Typography>
        {vuln.technique === 'stacked' && (
          <Alert severity="error" variant="outlined" className="mt-2">
            {t('vulnDetail.stackedWarning')}
          </Alert>
        )}
      </Paper>

      {vuln.evidence && (
        <Paper variant="outlined" className="p-3 bg-gray-50">
          <Typography variant="subtitle2" fontWeight={600} className="mb-1">
            {t('vulnDetail.evidenceTitle')}
          </Typography>
          <pre className="payload text-xs text-gray-700">{vuln.evidence}</pre>
        </Paper>
      )}

      {request && (
        <Paper variant="outlined" className="p-3 bg-gray-50">
          <Typography variant="subtitle2" fontWeight={600} className="mb-1">
            {t('vulnDetail.requestTitle')}
          </Typography>
          <pre className="payload text-xs text-gray-700">
            {formatRequestEvidence(request).join('\n')}
          </pre>
        </Paper>
      )}

      {/* 复现方式（PoC）：仅当报告带 poc 字段（导出路径生成）时渲染，缺失整块隐藏 */}
      {vuln.poc && <PocSection poc={vuln.poc} />}

      {vuln.trace && <BlindTraceTimeline trace={vuln.trace} />}
      <PayloadViewer payloads={vuln.payloads} />
    </Box>
  );
}
