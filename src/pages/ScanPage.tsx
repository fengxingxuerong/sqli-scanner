import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Paper,
  Button,
  Stack,
  Typography,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Alert,
  Box,
  ToggleButton,
  ToggleButtonGroup,
  Skeleton,
} from '@mui/material';
import TargetForm from '../components/TargetForm';
import ScanConfigPanel from '../components/ScanConfigPanel';
import SqlmapOptions from '../components/SqlmapOptions';
import ProgressView from '../components/ProgressView';
import InjectionTopologyGraph from '../components/InjectionTopologyGraph';
import { useScan } from '../hooks/useScan';
import { useEvents } from '../hooks/useEvents';
import { useScanStore } from '../store/scanStore';
import { DEFAULT_CONFIG, DEFAULT_SQLMAP_CONFIG } from '../shared/constants';
import { tauriBridge } from '../shared/tauriBridge';
import type { MethodType, ScanConfig, EngineType, SqlmapConfig } from '../shared/types';

// 解析 JSON 文本，失败返回空对象并提示
function parseJson(text: string): Record<string, string> {
  if (!text.trim()) return {};
  return JSON.parse(text);
}

// 扫描页：目标录入 + 配置 + 二次确认 + 实时进度（混合架构：自带引擎 / sqlmap）
export default function ScanPage() {
  const navigate = useNavigate();
  const { startScan, stopScan } = useScan();
  const { scanId, status, report, engine, setEngine, setStatus, wafSuggestion, secondOrderDiscovery, discoveredPoints, targetUrl, confirmedVulnPointIds } = useScanStore();
  useEvents(scanId);

  const [url, setUrl] = useState('');
  const [method, setMethod] = useState<MethodType>('GET');
  const [bodyText, setBodyText] = useState('');
  const [cookieText, setCookieText] = useState('');
  const [headerText, setHeaderText] = useState('');
  const [config, setConfig] = useState<ScanConfig>({ ...DEFAULT_CONFIG });
  const [sqlmapConfig, setSqlmapConfig] = useState<SqlmapConfig>({ ...DEFAULT_SQLMAP_CONFIG });
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [sqlConfirmOpen, setSqlConfirmOpen] = useState(false);
  const [error, setError] = useState('');
  // 提交中（startScan 异步调用期间）：显示骨架屏占位，避免重复点击与空白感
  const [submitting, setSubmitting] = useState(false);

  const running = status === 'running';

  // WAF 识别建议：一键应用只写入推荐插件，enabled 仍由用户显式开启（仅推荐，不自动套用）
  const applyWafSuggestion = () => {
    if (!wafSuggestion || !wafSuggestion.suggestions.length) return;
    const recommended = wafSuggestion.suggestions[0].plugins;
    setConfig((c) => ({
      ...c,
      wafEvasion: {
        ...c.wafEvasion,
        tamper: { ...c.wafEvasion.tamper, plugins: [...recommended] },
      },
    }));
  };

  const sqlDestructive =
    engine === 'sqlmap' && (sqlmapConfig.dump || sqlmapConfig.osShell || !!sqlmapConfig.fileRead);

  const handleStart = async () => {
    setError('');
    if (!url.trim()) {
      setError('请填写目标 URL');
      return;
    }
    let bodyParams = {};
    let cookieParams = {};
    let headerParams = {};
    const parseField = (text: string, name: string): Record<string, string> => {
      try {
        return parseJson(text);
      } catch {
        setError(`${name} 需为合法 JSON`);
        throw new Error('invalid-json');
      }
    };
    try {
      bodyParams = parseField(bodyText, 'Body');
      cookieParams = parseField(cookieText, 'Cookie');
      headerParams = parseField(headerText, 'Header');
    } catch {
      return;
    }

    // 自带引擎拖库：二次确认
    if (engine === 'builtin' && config.enableExtract) {
      setConfirmOpen(true);
      return;
    }
    // sqlmap 破坏性操作：二次确认
    if (engine === 'sqlmap' && sqlDestructive) {
      setSqlConfirmOpen(true);
      return;
    }
    await doStart(bodyParams, cookieParams, headerParams);
  };

  const doStart = async (
    bodyParams: Record<string, string>,
    cookieParams: Record<string, string>,
    headerParams: Record<string, string>
  ) => {
    setSubmitting(true);
    try {
      await tauriBridge.startEngine();
      await startScan({
        engine,
        url: url.trim(),
        method,
        bodyParams,
        cookieParams,
        headerParams,
        // 容错：确保 techniques 字段存在（老配置/历史恢复可能缺失）
        config: { ...config, techniques: config.techniques ?? DEFAULT_CONFIG.techniques },
        sqlmapConfig,
      });
    } catch (e: any) {
      setError(e.message || '启动扫描失败');
      setStatus('error');
    } finally {
      setSubmitting(false);
    }
  };

  // 解析三段参数并启动：任一非法 JSON 已在对应回调中报错并中止
  const parseAndStart = async () => {
    let bodyParams = {};
    let cookieParams = {};
    let headerParams = {};
    try {
      bodyParams = parseJson(bodyText);
      cookieParams = parseJson(cookieText);
      headerParams = parseJson(headerText);
    } catch {
      setError('参数解析失败（Body / Cookie / Header 需为合法 JSON）');
      return;
    }
    await doStart(bodyParams, cookieParams, headerParams);
  };

  const onConfirmExtract = async () => {
    setConfirmOpen(false);
    await parseAndStart();
  };

  const onConfirmSqlmap = async () => {
    setSqlConfirmOpen(false);
    await parseAndStart();
  };

  return (
    <Container maxWidth="md" className="py-6">
      <Typography variant="h5" fontWeight={700} className="mb-4">
        SQL 注入检测
      </Typography>

      {error && <Alert severity="error" className="mb-3">{error}</Alert>}

      <Paper className="p-4 space-y-4" variant="outlined">
        <Box className="flex items-center gap-3">
          <Typography variant="subtitle2" color="text.secondary">检测引擎</Typography>
          <ToggleButtonGroup
            value={engine}
            exclusive
            size="small"
            onChange={(_, v: EngineType | null) => v && setEngine(v)}
          >
            <ToggleButton value="builtin">自带引擎（教学/合规）</ToggleButton>
            <ToggleButton value="sqlmap">sqlmap 高级模式</ToggleButton>
          </ToggleButtonGroup>
        </Box>

        <TargetForm
          url={url}
          method={method}
          bodyText={bodyText}
          cookieText={cookieText}
          headerText={headerText}
          onChange={(p) => {
            if (p.url !== undefined) setUrl(p.url);
            if (p.method !== undefined) setMethod(p.method);
            if (p.bodyText !== undefined) setBodyText(p.bodyText);
            if (p.cookieText !== undefined) setCookieText(p.cookieText);
            if (p.headerText !== undefined) setHeaderText(p.headerText);
          }}
        />
        {wafSuggestion && wafSuggestion.vendors.length > 0 && (
          <Alert
            severity="info"
            variant="outlined"
            className="mt-3"
            action={
              <Button color="primary" size="small" onClick={applyWafSuggestion}>
                一键应用推荐
              </Button>
            }
          >
            识别到 WAF：
            <b>{wafSuggestion.vendors.map((v) => `${v.vendor}`).join('、')}</b>
            ，建议 tamper 组合：
            <b>{wafSuggestion.suggestions[0]?.plugins.join(' + ') || '—'}</b>
            （应用后需手动开启「启用 tamper 变换」）。
          </Alert>
        )}
        {secondOrderDiscovery && (
          <Alert severity="info" variant="outlined" className="mt-3">
            二阶自动发现：从 {secondOrderDiscovery.candidates.length} 个候选链接中确认{' '}
            {secondOrderDiscovery.confirmed.length} 个会回显存储内容的触发页。
            {secondOrderDiscovery.confirmed.length > 0 && (
              <Box component="ul" sx={{ m: 0, pl: 2, mt: 1 }}>
                {secondOrderDiscovery.confirmed.map((u, i) => (
                  <Box component="li" key={`${u}-${i}`}>
                    <Typography variant="body2" sx={{ wordBreak: 'break-all' }}>{u}</Typography>
                  </Box>
                ))}
              </Box>
            )}
          </Alert>
        )}
        {discoveredPoints.length > 0 && (
          <Box className="mt-2">
            <Typography variant="subtitle2" fontWeight={700}>注入点全景拓扑（实时）</Typography>
            <InjectionTopologyGraph
              points={discoveredPoints}
              baseUrl={targetUrl || ''}
              secondOrder={
                secondOrderDiscovery
                  ? { confirmed: secondOrderDiscovery.confirmed, storePoints: secondOrderDiscovery.storePoints || [] }
                  : undefined
              }
              highlightPointIds={confirmedVulnPointIds}
              height={Math.max(
                360,
                20 + discoveredPoints.length * 56 + (secondOrderDiscovery?.confirmed.length || 0) * 40,
              )}
            />
          </Box>
        )}
        <ScanConfigPanel
          config={config}
          mode={engine}
          onChange={(patch) => setConfig({ ...config, ...patch })}
          wafSuggestion={wafSuggestion?.suggestions}
        />
        {engine === 'sqlmap' && (
          <SqlmapOptions
            config={sqlmapConfig}
            onChange={(patch) => setSqlmapConfig({ ...sqlmapConfig, ...patch })}
          />
        )}
        <Stack direction="row" spacing={2}>
          <Button variant="contained" onClick={handleStart} disabled={running || submitting}>
            {running ? '扫描中…' : submitting ? '启动中…' : '开始扫描'}
          </Button>
          <Button
            variant="outlined"
            color="warning"
            disabled={!running}
            onClick={() => scanId && stopScan(scanId)}
          >
            停止
          </Button>
          {report && status === 'completed' && scanId && (
            <Button variant="text" onClick={() => navigate(`/report/${scanId}`)}>
              查看报告 →
            </Button>
          )}
        </Stack>
      </Paper>

      <Paper className="p-4 mt-4" variant="outlined">
        {submitting ? (
          <Box className="space-y-3" aria-busy="true">
            <Skeleton variant="text" width="30%" height={32} />
            <Skeleton variant="rectangular" height={12} />
            <Box className="flex flex-wrap gap-2">
              {Array.from({ length: 6 }).map((_, i) => (
                <Skeleton key={i} variant="rectangular" width={120} height={64} />
              ))}
            </Box>
          </Box>
        ) : (
          <ProgressView />
        )}
      </Paper>

      {report && status === 'completed' && (
        <Alert severity="info" className="mt-3">
          扫描完成，风险等级：<b>{report.riskLevel}</b>，发现漏洞 {report.vulns.length} 个。
        </Alert>
      )}

      {/* 自带引擎拖库二次确认 */}
      <Dialog open={confirmOpen} onClose={() => setConfirmOpen(false)}>
        <DialogTitle>确认执行数据提取（拖库）？</DialogTitle>
        <DialogContent>
          <DialogContentText>
            你已开启「拖库」功能，工具将尝试提取数据库中的库/表/列/数据。请仅在<b>授权环境</b>下继续，未授权目标可能违法。
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmOpen(false)}>取消</Button>
          <Button variant="contained" color="warning" onClick={onConfirmExtract}>
            我已知晓，继续
          </Button>
        </DialogActions>
      </Dialog>

      {/* sqlmap 破坏性操作二次确认 */}
      <Dialog open={sqlConfirmOpen} onClose={() => setSqlConfirmOpen(false)}>
        <DialogTitle>确认执行 sqlmap 破坏性操作？</DialogTitle>
        <DialogContent>
          <DialogContentText>
            你已开启拖库 / OS Shell / 读文件，sqlmap 将对目标执行<b>写/读/命令</b>操作。请仅在<b>已授权目标</b>上继续，否则可能违法或造成破坏。
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSqlConfirmOpen(false)}>取消</Button>
          <Button variant="contained" color="error" onClick={onConfirmSqlmap}>
            我已知晓，继续
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
}
