import { Alert, Stack } from '@mui/material';
import type { ScanConfig } from '../shared/types';

/**
 * 技术门控前置校验组件（对标 sqlmap 各类技术的启用前置条件）。
 *
 * 把原先散落在 ScanConfigPanel 二阶区块与 OOB 区块的三处「开关联动校验」前置提示
 * 统一收口到一张规则表，新增门控只需追加一条 GateRule，无需再改 UI 布局。
 *
 * 用 scope 区分所属 UI 区块（'secondOrder' | 'oob'），保证同一门控不会在不同区块重复渲染。
 * 纯前端前置提示，不阻塞提交；后端 riskGate / 接收端开关等仍各自兜底。
 */

type GateScope = 'secondOrder' | 'oob';

interface GateRule {
  scope: GateScope;
  severity: 'info' | 'warning';
  /** 命中条件 */
  when: (c: ScanConfig) => boolean;
  /** 提示文案（可读取 config 动态插值，如 risk 当前值） */
  message: (c: ScanConfig) => string;
}

const GATE_RULES: GateRule[] = [
  {
    // 二阶 oobTrigger 开启，但 OOB 接收端未启用 → 触发页无法经 OOB 回传确认
    scope: 'secondOrder',
    severity: 'info',
    when: (c) => !!c.secondOrder?.oobTrigger && !c.oob?.enabled,
    message: () =>
      'oobTrigger 已开启，但 OOB 接收端未启用（config.oob.enabled=false），触发页将无法经 OOB 通道回传确认。',
  },
  {
    // 勾选 oob 技术但未启用接收端 → OOB 检测不会运行
    scope: 'oob',
    severity: 'info',
    when: (c) => (c.techniques || []).includes('oob') && !c.oob?.enabled,
    message: () =>
      '已勾选「带外注入(OOB)」技术，但接收端未启用（config.oob.enabled=false），OOB 检测不会运行。',
  },
  {
    // 勾选 oob 且启用接收端，但 risk<3 → 将被后端风险门控拦截
    scope: 'oob',
    severity: 'warning',
    when: (c) => (c.techniques || []).includes('oob') && !!c.oob?.enabled && (c.risk ?? 1) < 3,
    message: (c) =>
      `OOB 带外需风险等级 risk≥3，当前 risk=${c.risk ?? 1}，OOB 将被风险门控拦截（请提升风险等级或确保 --risk≥3）。`,
  },
];

export default function TechniqueGateAlerts({ config, scope }: { config: ScanConfig; scope: GateScope }) {
  const alerts = GATE_RULES.filter((r) => r.scope === scope && r.when(config));
  if (alerts.length === 0) return null;
  return (
    <Stack spacing={1} className="mt-2">
      {alerts.map((r, i) => (
        <Alert key={i} severity={r.severity} variant="outlined">
          {r.message(config)}
        </Alert>
      ))}
    </Stack>
  );
}
