import { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Grid,
  TextField,
  FormControlLabel,
  Switch,
  FormHelperText,
  Divider,
  Alert,
  FormControl,
  FormGroup,
  Checkbox,
  MenuItem,
  Slider,
  ToggleButton,
  ToggleButtonGroup,
  Button,
} from '@mui/material';
import type { ScanConfig, AuthConfig, EngineType, WafSuggestion } from '../shared/types';
import { TECHNIQUES, TECHNIQUE_LABEL, DEFAULT_CONFIG, SCAN_PRESETS, SCAN_PRESET_LABEL, SCAN_DEFAULTS } from '../shared/constants';
import WafTamperPanel from './WafTamperPanel';
import TechniqueGateAlerts from './TechniqueGateAlerts';

// 解析自定义 Header JSON 文本（容错：非法 JSON 返回 null）
function parseHeaders(text: string): Record<string, string> | null {
  if (!text.trim()) return {};
  try {
    const obj = JSON.parse(text);
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
      return obj as Record<string, string>;
    }
    return null;
  } catch {
    return null;
  }
}

// 比较 config 的 7 个性能字段与预设，完全匹配则返回该档位 key（档位高亮联动）；否则 null
const PRESET_PERF_FIELDS = ['concurrency', 'timeoutMs', 'retry', 'timeThresholdMs', 'ratePerSec', 'level', 'risk'] as const;
function matchPreset(config: ScanConfig): keyof typeof SCAN_PRESETS | null {
  const cfg = config as unknown as Record<string, unknown>;
  for (const key of Object.keys(SCAN_PRESETS) as (keyof typeof SCAN_PRESETS)[]) {
    const p = SCAN_PRESETS[key] as unknown as Record<string, unknown>;
    if (PRESET_PERF_FIELDS.every((f) => cfg[f] === p[f])) return key;
  }
  return null;
}

// 扫描配置区：超时 / 并发 / 重试 / 阈值 / 限速 / 拖库 + 代理 / 认证 / WAF 规避
export default function ScanConfigPanel({
  config,
  onChange,
  mode = 'builtin',
  wafSuggestion,
}: {
  config: ScanConfig;
  onChange: (patch: Partial<ScanConfig>) => void;
  mode?: EngineType;
  wafSuggestion?: WafSuggestion[];
}) {
  // 认证面板中的「自定义 Header」以 JSON 文本录入，解析后写入 config.auth.headers
  const [headersText, setHeadersText] = useState('');

  // 预设档位高亮：由当前 config 性能字段派生（与某预设完全一致才高亮，手动微调后自动消高亮）
  const preset = matchPreset(config);
  const applyPreset = (key: keyof typeof SCAN_PRESETS) => {
    onChange(SCAN_PRESETS[key]);
  };

  // 恢复默认：仅重置性能参数到出厂值（不含认证/代理/WAF/二阶/OOB）
  const applyDefaults = () => {
    onChange(SCAN_DEFAULTS);
  };

  // 外部 auth.headers 变化时同步文本（避免受控输入抖动）
  useEffect(() => {
    const h = config.auth?.headers;
    setHeadersText(h && Object.keys(h).length > 0 ? JSON.stringify(h, null, 2) : '');
  }, [config.auth?.headers]);

  // 更新 auth 嵌套对象（整体替换）
  const updateAuth = (patch: Partial<AuthConfig>) => {
    onChange({ auth: { ...(config.auth || {}), ...patch } });
  };

  // 更新 wafEvasion 嵌套对象（整体替换）
  const updateWaf = (patch: Partial<ScanConfig['wafEvasion']>) => {
    onChange({ wafEvasion: { ...config.wafEvasion, ...patch } });
  };

  return (
    <Box className="space-y-3">
      <Typography variant="subtitle1" fontWeight={600}>
        扫描配置
      </Typography>
      {mode === 'builtin' && (
        <Box className="mb-2">
          <Box className="flex items-center justify-between mb-1">
            <Typography variant="caption" color="text.secondary">
              预设档位（一键套用性能建议值，应用后仍可手动微调）
            </Typography>
            <Button
              size="small"
              variant="outlined"
              color="inherit"
              onClick={applyDefaults}
            >
              恢复默认
            </Button>
          </Box>
          <ToggleButtonGroup
            exclusive
            size="small"
            value={preset}
            onChange={(_e, v) => {
              if (v) applyPreset(v as keyof typeof SCAN_PRESETS);
            }}
          >
            <ToggleButton value="quick">{SCAN_PRESET_LABEL.quick}</ToggleButton>
            <ToggleButton value="standard">{SCAN_PRESET_LABEL.standard}</ToggleButton>
            <ToggleButton value="aggressive">{SCAN_PRESET_LABEL.aggressive}</ToggleButton>
          </ToggleButtonGroup>
          <FormHelperText>
            快速=低负载低风险 · 标准=均衡 · 激进=高覆盖高负载(risk=3，不含二阶/OOB)；「恢复默认」回到出厂性能配置
          </FormHelperText>
        </Box>
      )}
      {mode === 'builtin' && (
      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <Box>
            <Box className="flex items-center justify-between">
              <Typography variant="caption" color="text.secondary">并发数</Typography>
              <Typography variant="body2" fontWeight={600}>{config.concurrency}</Typography>
            </Box>
            <Slider
              min={1}
              max={20}
              step={1}
              value={config.concurrency}
              aria-label="并发数"
              onChange={(_, v) => onChange({ concurrency: v as number })}
              valueLabelDisplay="auto"
              marks={[
                { value: 1, label: '1' },
                { value: 10, label: '10' },
                { value: 20, label: '20' },
              ]}
              size="small"
            />
          </Box>
        </Grid>
        <Grid item xs={12} md={4}>
          <Box>
            <Box className="flex items-center justify-between">
              <Typography variant="caption" color="text.secondary">超时 (ms)</Typography>
              <Typography variant="body2" fontWeight={600}>{config.timeoutMs ?? 5000}</Typography>
            </Box>
            <Slider
              min={1000}
              max={60000}
              step={500}
              value={config.timeoutMs ?? 5000}
              aria-label="超时 (ms)"
              onChange={(_, v) => onChange({ timeoutMs: v as number })}
              valueLabelDisplay="auto"
              marks={[
                { value: 1000, label: '1s' },
                { value: 30000, label: '30s' },
                { value: 60000, label: '60s' },
              ]}
              size="small"
            />
          </Box>
        </Grid>
        <Grid item xs={12} md={4}>
          <Box>
            <Box className="flex items-center justify-between">
              <Typography variant="caption" color="text.secondary">重试次数</Typography>
              <Typography variant="body2" fontWeight={600}>{config.retry ?? 0}</Typography>
            </Box>
            <Slider
              min={0}
              max={5}
              step={1}
              value={config.retry ?? 0}
              aria-label="重试次数"
              onChange={(_, v) => onChange({ retry: v as number })}
              valueLabelDisplay="auto"
              marks={[
                { value: 0, label: '0' },
                { value: 5, label: '5' },
              ]}
              size="small"
            />
          </Box>
        </Grid>
        <Grid item xs={12} md={4}>
          <Box>
            <Box className="flex items-center justify-between">
              <Typography variant="caption" color="text.secondary">时间盲注阈值 (ms)</Typography>
              <Typography variant="body2" fontWeight={600}>{config.timeThresholdMs ?? 500}</Typography>
            </Box>
            <Slider
              min={100}
              max={5000}
              step={100}
              value={config.timeThresholdMs ?? 500}
              aria-label="时间盲注阈值 (ms)"
              onChange={(_, v) => onChange({ timeThresholdMs: v as number })}
              valueLabelDisplay="auto"
              marks={[
                { value: 100, label: '100' },
                { value: 2500, label: '2500' },
                { value: 5000, label: '5000' },
              ]}
              size="small"
            />
          </Box>
        </Grid>
        <Grid item xs={12} md={4}>
          <Box>
            <Box className="flex items-center justify-between">
              <Typography variant="caption" color="text.secondary">限速 (req/s)</Typography>
              <Typography variant="body2" fontWeight={600}>{config.ratePerSec ?? 10}</Typography>
            </Box>
            <Slider
              min={1}
              max={100}
              step={1}
              value={config.ratePerSec ?? 10}
              aria-label="限速 (req/s)"
              onChange={(_, v) => onChange({ ratePerSec: v as number })}
              valueLabelDisplay="auto"
              marks={[
                { value: 1, label: '1' },
                { value: 50, label: '50' },
                { value: 100, label: '100' },
              ]}
              size="small"
            />
          </Box>
        </Grid>
        <Grid item xs={12} md={4} className="flex items-center">
          <FormControlLabel
            control={
              <Switch
                checked={config.enableExtract}
                onChange={(e) => onChange({ enableExtract: e.target.checked })}
              />
            }
            label="启用拖库（数据提取）"
          />
        </Grid>
      </Grid>)}

      <Divider className="my-2" />
      <Typography variant="subtitle2" fontWeight={600} color="text.secondary">
        代理 / 认证（随配置持久化，明文保存于本地）
      </Typography>
      <Grid container spacing={2}>
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            label="代理地址"
            placeholder="http://127.0.0.1:8080 或 socks5://127.0.0.1:1080"
            value={config.proxy ?? ''}
            onChange={(e) => onChange({ proxy: e.target.value.trim() || null })}
            helperText="支持 HTTP/HTTPS 与 SOCKS5 代理；留空表示直连"
          />
        </Grid>
        <Grid item xs={6} md={3}>
          <TextField
            fullWidth
            label="Basic Auth 用户名"
            value={config.auth?.basic?.username ?? ''}
            onChange={(e) =>
              updateAuth({
                basic: { username: e.target.value, password: config.auth?.basic?.password ?? '' },
              })
            }
          />
        </Grid>
        <Grid item xs={6} md={3}>
          <TextField
            fullWidth
            type="password"
            label="Basic Auth 密码"
            value={config.auth?.basic?.password ?? ''}
            onChange={(e) =>
              updateAuth({
                basic: { username: config.auth?.basic?.username ?? '', password: e.target.value },
              })
            }
          />
        </Grid>
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            label="自定义 Cookie"
            placeholder="sessionid=abc123; token=xyz"
            value={config.auth?.cookie ?? ''}
            onChange={(e) => updateAuth({ cookie: e.target.value.trim() || undefined })}
          />
        </Grid>
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            multiline
            minRows={2}
            label="自定义 Header (JSON)"
            placeholder={'{\n  "X-Forwarded-For": "127.0.0.1"\n}'}
            value={headersText}
            onChange={(e) => {
              const text = e.target.value;
              setHeadersText(text);
              const parsed = parseHeaders(text);
              if (parsed) updateAuth({ headers: parsed });
            }}
            error={headersText.trim() !== '' && parseHeaders(headersText) === null}
            helperText="键值对 JSON，将随每次请求发送（与目标的 Header 参数合并）"
          />
        </Grid>
      </Grid>
      <Alert severity="warning" variant="outlined" className="mt-1">
        凭证与代理以明文保存于本地，请勿在公共设备使用。
      </Alert>

      <Divider className="my-2" />
      <Typography variant="subtitle2" fontWeight={600} color="text.secondary">
        检测技术（默认 4 类全选，堆叠注入按需开启）
      </Typography>
      {mode === 'builtin' && (
      <FormControl component="fieldset" className="mt-1">
        <FormGroup row>
          {TECHNIQUES.map((t) => {
            const selected = (config.techniques ?? DEFAULT_CONFIG.techniques).includes(t);
            return (
              <FormControlLabel
                key={t}
                control={
                  <Checkbox
                    checked={selected}
                    onChange={(e) => {
                      const base = config.techniques ?? DEFAULT_CONFIG.techniques;
                      const next = e.target.checked
                        ? [...base, t]
                        : base.filter((x) => x !== t);
                      onChange({ techniques: next });
                    }}
                  />
                }
                label={TECHNIQUE_LABEL[t]}
              />
            );
          })}
        </FormGroup>
        <Alert severity="info" variant="outlined" className="mt-1" sx={{ maxWidth: 520 }}>
          堆叠注入可确认目标是否允许执行多条语句，风险高（命中即「严重」），默认不开启；MySQL 需开启 multiStatements 才能触发，Oracle 不适用。
        </Alert>
      </FormControl>)}
      {/* 高级检测选项（对标 sqlmap）：level/risk/timeSec/delay/detectMatch/safeProbe/hpp/keepAlive */}
      {mode === 'builtin' && (<>
        <Divider className="my-2" />
        <Typography variant="subtitle2" fontWeight={600} color="text.secondary">
          高级检测选项（对标 sqlmap）
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={6} md={3}>
            <TextField
              select
              fullWidth
              label="检测等级 level"
              value={config.level}
              onChange={(e) => onChange({ level: Number(e.target.value) })}
              helperText="1-5：越高测越多位置（含 Cookie/Header）"
            >
              {[1, 2, 3, 4, 5].map((n) => (
                <MenuItem key={n} value={n}>{n}</MenuItem>
              ))}
            </TextField>
          </Grid>
          <Grid item xs={6} md={3}>
            <TextField
              select
              fullWidth
              label="风险等级 risk"
              value={config.risk}
              onChange={(e) => onChange({ risk: Number(e.target.value) })}
              helperText="1-3：越高启用堆叠/OOB 等高风险技术"
            >
              {[1, 2, 3].map((n) => (
                <MenuItem key={n} value={n}>{n}</MenuItem>
              ))}
            </TextField>
          </Grid>
          <Grid item xs={12} md={3}>
            <Box>
              <Box className="flex items-center justify-between">
                <Typography variant="caption" color="text.secondary">时间盲注 SLEEP (s)</Typography>
                <Typography variant="body2" fontWeight={600}>{config.timeSec ?? 2}</Typography>
              </Box>
              <Slider
                min={1}
                max={10}
                step={1}
                value={config.timeSec ?? 2}
                aria-label="时间盲注 SLEEP (s)"
                onChange={(_, v) => onChange({ timeSec: v as number })}
                valueLabelDisplay="auto"
                marks={[
                  { value: 1, label: '1' },
                  { value: 10, label: '10' },
                ]}
                size="small"
              />
            </Box>
            <FormHelperText>--time-sec，触发延迟秒数</FormHelperText>
          </Grid>
          <Grid item xs={12} md={3}>
            <Box>
              <Box className="flex items-center justify-between">
                <Typography variant="caption" color="text.secondary">固定延时 (ms)</Typography>
                <Typography variant="body2" fontWeight={600}>{config.requestDelayMs ?? 0}</Typography>
              </Box>
              <Slider
                min={0}
                max={2000}
                step={50}
                value={config.requestDelayMs ?? 0}
                aria-label="固定延时 (ms)"
                onChange={(_, v) => onChange({ requestDelayMs: v as number })}
                valueLabelDisplay="auto"
                marks={[
                  { value: 0, label: '0' },
                  { value: 1000, label: '1000' },
                  { value: 2000, label: '2000' },
                ]}
                size="small"
              />
            </Box>
            <FormHelperText>--delay，每次请求前固定休眠</FormHelperText>
          </Grid>
        </Grid>

        <Typography variant="caption" color="text.secondary" className="mt-2">
          自定义判定锚点（对标 --string/--not-string/--regexp/--code；留空走统计判定）
        </Typography>
        <Grid container spacing={2} className="mt-1">
          <Grid item xs={12} md={3}>
            <TextField
              fullWidth
              label="真响应含此串"
              placeholder="--string"
              value={config.detectMatch?.string ?? ''}
              onChange={(e) =>
                onChange({ detectMatch: { ...config.detectMatch, string: e.target.value.trim() || undefined } })
              }
            />
          </Grid>
          <Grid item xs={12} md={3}>
            <TextField
              fullWidth
              label="真响应不含此串"
              placeholder="--not-string"
              value={config.detectMatch?.notString ?? ''}
              onChange={(e) =>
                onChange({ detectMatch: { ...config.detectMatch, notString: e.target.value.trim() || undefined } })
              }
            />
          </Grid>
          <Grid item xs={12} md={3}>
            <TextField
              fullWidth
              label="真响应匹配正则"
              placeholder="--regexp"
              value={config.detectMatch?.regexp ?? ''}
              onChange={(e) =>
                onChange({ detectMatch: { ...config.detectMatch, regexp: e.target.value.trim() || undefined } })
              }
            />
          </Grid>
          <Grid item xs={12} md={3}>
            <TextField
              fullWidth
              type="number"
              label="真响应状态码"
              placeholder="--code"
              value={config.detectMatch?.code ?? ''}
              onChange={(e) => {
                const v = e.target.value.trim();
                onChange({
                  detectMatch: { ...config.detectMatch, code: v === '' ? undefined : Number(v) },
                });
              }}
            />
          </Grid>
        </Grid>

        <Typography variant="caption" color="text.secondary" className="mt-2">
          安全间隔探测（对标 --safe-url/--safe-freq/--safe-order；偏离基线即告警）
        </Typography>
        <Grid container spacing={2} className="mt-1">
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              label="安全 URL（可逗号分隔多 URL 随机轮询）"
              placeholder="https://example.com/healthy"
              value={config.safeProbe?.url ?? ''}
              onChange={(e) =>
                onChange({ safeProbe: { ...config.safeProbe, url: e.target.value.trim() || undefined } })
              }
              helperText="确信无注入副作用、始终返回稳定内容的页面"
            />
          </Grid>
          <Grid item xs={6} md={3}>
            <TextField
              fullWidth
              type="number"
              label="探测频率（每 N 次请求）"
              value={config.safeProbe?.freq ?? 0}
              onChange={(e) =>
                onChange({ safeProbe: { ...config.safeProbe, freq: Number(e.target.value) || 0 } })
              }
              helperText="0=关闭"
            />
          </Grid>
          <Grid item xs={6} md={3} className="flex items-center">
            <FormControlLabel
              control={
                <Switch
                  checked={config.safeProbe?.randomize !== false}
                  onChange={(e) => onChange({ safeProbe: { ...config.safeProbe, randomize: e.target.checked } })}
                />
              }
              label="随机轮询多 URL（关=顺序 --safe-order）"
            />
          </Grid>
        </Grid>

        <Grid container spacing={2} className="mt-1">
          <Grid item xs={6} md={3} className="flex items-center">
            <FormControlLabel
              control={
                <Switch
                  checked={!!config.hpp}
                  onChange={(e) => onChange({ hpp: e.target.checked })}
                />
              }
              label="HTTP 参数污染 --hpp"
            />
          </Grid>
          <Grid item xs={6} md={3} className="flex items-center">
            <FormControlLabel
              control={
                <Switch
                  checked={config.keepAlive !== false}
                  onChange={(e) => onChange({ keepAlive: e.target.checked })}
                />
              }
              label="连接复用（关=--no-keep-alive）"
            />
          </Grid>

          {/* 二阶注入（对标 sqlmap --second-order）：开启对目标发起真实写请求，需明确授权 */}
          <Grid item xs={12}>
            <Alert severity="warning" variant="outlined">
              二阶注入开启后将向目标发起<strong>真实写请求</strong>（POST 注册 / 评论 / 资料等），存在数据污染与账号副作用，
              仅当你<strong>已明确授权</strong>该目标时启用；命中判定为高危。
            </Alert>
            {/* 二阶区块技术门控前置校验（含 oobTrigger 联动）统一收口到 TechniqueGateAlerts */}
            <TechniqueGateAlerts config={config} scope="secondOrder" />
            <Grid container spacing={2} className="mt-1">
              <Grid item xs={6} md={3} className="flex items-center">
                <FormControlLabel
                  control={
                    <Switch
                      checked={!!config.secondOrder?.enabled}
                      onChange={(e) =>
                        onChange({
                          secondOrder: {
                            ...(config.secondOrder || { triggerUrls: [] }),
                            enabled: e.target.checked,
                          },
                        })
                      }
                    />
                  }
                  label="启用二阶注入 --second-order"
                />
              </Grid>
              <Grid item xs={12} md={9}>
                <TextField
                  fullWidth
                  multiline
                  minRows={2}
                  label="触发页 URL（逗号或换行分隔）"
                  value={(config.secondOrder?.triggerUrls || []).join('\n')}
                  disabled={!config.secondOrder?.enabled}
                  onChange={(e) =>
                    onChange({
                      secondOrder: {
                        ...(config.secondOrder || { enabled: false }),
                        triggerUrls: e.target.value.split(/[,\n]/).map((s) => s.trim()).filter(Boolean),
                      },
                    })
                  }
                  helperText="确信会回显存储内容的页面（如个人资料页），用于验证一阶注入是否触发二阶执行；留空且开启「自动发现触发页」时由引擎自动探测"
                />
              </Grid>
              <Grid item xs={12} md={9}>
                <TextField
                  fullWidth
                  multiline
                  minRows={2}
                  label="指定存储点参数（逗号或换行分隔）"
                  value={(config.secondOrder?.manualStorePoints || []).join('\n')}
                  disabled={!config.secondOrder?.enabled}
                  onChange={(e) =>
                    onChange({
                      secondOrder: {
                        ...(config.secondOrder || { enabled: false, triggerUrls: [] }),
                        manualStorePoints: e.target.value.split(/[,\n]/).map((s) => s.trim()).filter(Boolean),
                      },
                    })
                  }
                  helperText="手动指定哪些参数名是存储型（如 username、email）；与扫描期启发式识别取并集，命中点将被标记为存储点并纳入二阶验证。适用于启发式漏判的场景"
                />
              </Grid>
              {/* 二阶进阶选项：刷新 CSRF / 负控制 / OOB 触发回传 / 触发页自动发现（对标 sqlmap 二阶细粒度） */}
              <Grid item xs={12}>
                <Grid container spacing={2}>
                  <Grid item xs={6} md={3} className="flex items-center">
                    <FormControlLabel
                      disabled={!config.secondOrder?.enabled}
                      control={
                        <Switch
                          checked={config.secondOrder?.refreshCsrf !== false}
                          onChange={(e) =>
                            onChange({
                              secondOrder: {
                                ...(config.secondOrder || { enabled: false, triggerUrls: [] }),
                                refreshCsrf: e.target.checked,
                              },
                            })
                          }
                        />
                      }
                      label="触发前刷新 CSRF"
                    />
                  </Grid>
                  <Grid item xs={6} md={3} className="flex items-center">
                    <FormControlLabel
                      disabled={!config.secondOrder?.enabled}
                      control={
                        <Switch
                          checked={config.secondOrder?.negativeControl !== false}
                          onChange={(e) =>
                            onChange({
                              secondOrder: {
                                ...(config.secondOrder || { enabled: false, triggerUrls: [] }),
                                negativeControl: e.target.checked,
                              },
                            })
                          }
                        />
                      }
                      label="负控制验证"
                    />
                  </Grid>
                  <Grid item xs={6} md={3} className="flex items-center">
                    <FormControlLabel
                      disabled={!config.secondOrder?.enabled}
                      control={
                        <Switch
                          checked={!!config.secondOrder?.oobTrigger}
                          onChange={(e) =>
                            onChange({
                              secondOrder: {
                                ...(config.secondOrder || { enabled: false, triggerUrls: [] }),
                                oobTrigger: e.target.checked,
                              },
                            })
                          }
                        />
                      }
                      label="OOB 触发回传"
                    />
                  </Grid>
                  <Grid item xs={6} md={3} className="flex items-center">
                    <FormControlLabel
                      disabled={!config.secondOrder?.enabled}
                      control={
                        <Switch
                          checked={!!config.secondOrder?.autoDiscover}
                          onChange={(e) =>
                            onChange({
                              secondOrder: {
                                ...(config.secondOrder || { enabled: false, triggerUrls: [] }),
                                autoDiscover: e.target.checked,
                              },
                            })
                          }
                        />
                      }
                      label="自动发现触发页"
                    />
                  </Grid>
                </Grid>
                <FormHelperText className="mt-1">
                  自动发现触发页：开启后若未手填触发页，将从目标页链接中自动发现候选触发页，并用哨兵值验证其是否回显存储内容（须已授权二阶写请求）。
                </FormHelperText>
              </Grid>
            </Grid>
          </Grid>

          {/* OOB 带外注入（对标 sqlmap 带外通道）：需 techniques 勾选 oob + risk>=3 + 此处启用接收端 */}
          <Grid item xs={12}>
            <Alert severity="warning" variant="outlined">
              OOB 带外注入将触发目标 DBMS<strong>向外部地址发起出站请求</strong>（DNS/SMB/HTTP 回连本机接收端），出站噪声大、易被监测，
              仅当你<strong>已明确授权</strong>该目标、且自有可达接收域名时启用；另需风险等级 <strong>risk≥3</strong> 且检测技术勾选「带外注入(OOB)」。
            </Alert>
            {/* OOB 区块技术门控前置校验（含「勾选未启用接收端」「启用但 risk<3」）统一收口到 TechniqueGateAlerts */}
            <TechniqueGateAlerts config={config} scope="oob" />
            <Grid container spacing={2} className="mt-1">
              <Grid item xs={6} md={3} className="flex items-center">
                <FormControlLabel
                  control={
                    <Switch
                      checked={!!config.oob?.enabled}
                      onChange={(e) =>
                        onChange({
                          oob: {
                            ...(config.oob || { callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 5000 }),
                            enabled: e.target.checked,
                          },
                        })
                      }
                    />
                  }
                  label="启用 OOB 带外接收端"
                />
              </Grid>
              <Grid item xs={6} md={4}>
                <TextField
                  fullWidth
                  label="接收端地址 callbackBase"
                  value={config.oob?.callbackBase || '127.0.0.1:8899'}
                  disabled={!config.oob?.enabled}
                  onChange={(e) =>
                    onChange({
                      oob: {
                        ...(config.oob || { enabled: false, httpPort: 8899, timeoutMs: 5000 }),
                        callbackBase: e.target.value,
                      },
                    })
                  }
                  helperText="目标 DBMS 回连地址（真实环境换成自有域名）"
                />
              </Grid>
              <Grid item xs={6} md={2}>
                <TextField
                  fullWidth
                  type="number"
                  label="接收端口"
                  value={config.oob?.httpPort ?? 8899}
                  disabled={!config.oob?.enabled}
                  onChange={(e) =>
                    onChange({
                      oob: {
                        ...(config.oob || { enabled: false, callbackBase: '127.0.0.1:8899', timeoutMs: 5000 }),
                        httpPort: Number(e.target.value),
                      },
                    })
                  }
                  helperText="独立监听端口（非引擎 4567）"
                />
              </Grid>
            </Grid>
          </Grid>
        </Grid>
      </>)}

      {mode === 'builtin' && (<>
      <Divider className="my-2" />
      <Typography variant="subtitle2" fontWeight={600} color="text.secondary">
        WAF 规避（默认关闭，必要时显式开启；开启后报告会标注）
      </Typography>
      <Grid container spacing={2}>
        <Grid item xs={12} md={4} className="flex items-center">
          <FormControlLabel
            control={
              <Switch
                checked={config.wafEvasion.randomUA}
                onChange={(e) => updateWaf({ randomUA: e.target.checked })}
              />
            }
            label="随机 User-Agent"
          />
        </Grid>
        <Grid item xs={12} md={4} className="flex items-center">
          <FormControlLabel
            control={
              <Switch
                checked={config.wafEvasion.obfuscate}
                onChange={(e) => updateWaf({ obfuscate: e.target.checked })}
              />
            }
            label="Payload 混淆（legacy，已被 tamper 取代）"
          />
        </Grid>
        <Grid item xs={12} md={4}>
          <Box>
            <Box className="flex items-center justify-between">
              <Typography variant="caption" color="text.secondary">请求间随机延时 (ms)</Typography>
              <Typography variant="body2" fontWeight={600}>{config.wafEvasion.jitterMs ?? 0}</Typography>
            </Box>
            <Slider
              min={0}
              max={2000}
              step={50}
              value={config.wafEvasion.jitterMs ?? 0}
              aria-label="请求间随机延时 (ms)"
              onChange={(_, v) => updateWaf({ jitterMs: v as number })}
              valueLabelDisplay="auto"
              marks={[
                { value: 0, label: '0' },
                { value: 1000, label: '1000' },
                { value: 2000, label: '2000' },
              ]}
              size="small"
            />
          </Box>
          <FormHelperText>0 表示不延时</FormHelperText>
        </Grid>
      </Grid>
      <Box className="mt-2">
        <Typography variant="caption" color="text.secondary">
          tamper 链式变换（对标 sqlmap --tamper）：多选 + 强度 + 顺序，默认全关；开启后报告标注所用组合
        </Typography>
        <WafTamperPanel
          value={config.wafEvasion.tamper}
          onChange={(t) => updateWaf({ tamper: t })}
          suggestion={wafSuggestion}
        />
      </Box></>)}
    </Box>
  );
}
