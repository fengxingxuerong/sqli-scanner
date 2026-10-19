// ============================================================================
// CyberLed —— 赛博状态指示灯（D107 桌面端 UI 全面优化）
//
// 四种状态一码：在线(绿) / 运行(青呼吸) / 告警(琥珀) / 危险(品红脉冲)。
// 之前「扫描中」指示是 TopNav 里内联的一段 div（颜色/动画各写一遍），
// 进度页另有自己的一套 —— 语义相同却两处实现。收敛后状态语义单一真源。
// 无障碍：灯本身是装饰（aria-hidden），语义由相邻 label 文本承载。
// ============================================================================
import { Box, Typography } from '@mui/material';

export type CyberLedState = 'online' | 'busy' | 'warn' | 'danger';

interface CyberLedProps {
  state: CyberLedState;
  /** 灯右侧文字说明；不传则只渲染灯 */
  label?: string;
}

export default function CyberLed({ state, label }: CyberLedProps) {
  const colorVar = `var(--cy-${state === 'busy' ? 'cyan' : state === 'online' ? 'lime' : state === 'warn' ? 'amber' : 'magenta'})`;
  return (
    <Box component="span" className="flex items-center gap-1.5" sx={{ color: colorVar }}>
      <Box component="span" className={`cyber-led cyber-led--${state}`} aria-hidden="true" />
      {label && (
        <Typography component="span" variant="caption" fontWeight={700} className="mono">
          {label}
        </Typography>
      )}
    </Box>
  );
}
