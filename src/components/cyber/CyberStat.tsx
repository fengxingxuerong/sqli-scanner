// ============================================================================
// CyberStat —— 赛博数据卡（D107 桌面端 UI 全面优化）
//
// 首页/报告页共用的「数字结论」卡片：大号等宽数字 + 标签 + 一句话释义。
// 设计取向：**数字先于文字** —— 扫描类工具用户第一眼要的是「多少」，
// 标签与释义负责解释「这个数是什么、怎么来的」，避免纯数字看不懂。
// ============================================================================
import type { ReactNode } from 'react';
import { Box, Paper, Stack, Typography } from '@mui/material';

export type CyberStatTone = 'cyan' | 'violet' | 'danger' | 'warn' | 'success' | 'neutral';

/** 语义色 → CSS 变量（与 cyber.css 同源，避免组件里再硬编码一份颜色） */
const TONE_COLOR: Record<CyberStatTone, string> = {
  cyan: 'var(--cy-cyan)',
  violet: 'var(--cy-violet)',
  danger: 'var(--cy-magenta)',
  warn: 'var(--cy-amber)',
  success: 'var(--cy-lime)',
  neutral: 'var(--cy-text-faint)',
};

interface CyberStatProps {
  /** 主数字（或短字符串，如风险等级 Critical） */
  value: ReactNode;
  /** 数字下方的名称 */
  label: string;
  /** 再下方的一句话释义：这个数怎么来的 / 代表什么 */
  hint?: string;
  /** 左上图标 */
  icon?: ReactNode;
  tone?: CyberStatTone;
}

export default function CyberStat({ value, label, hint, icon, tone = 'cyan' }: CyberStatProps) {
  const color = TONE_COLOR[tone];
  return (
    <Paper
      variant="outlined"
      className="cyber-panel cyber-stat cyber-clip"
      sx={{
        height: '100%',
        borderRadius: 0,
        p: 2,
        transition: 'transform 0.18s ease, border-color 0.18s ease',
        '&:hover': { transform: 'translateY(-2px)', borderColor: 'var(--cy-line-strong)' },
      }}
    >
      <Box className="cyber-stat__bar" sx={{ background: `linear-gradient(180deg, ${color} 0%, var(--cy-violet) 100%)` }} />
      <Stack direction="row" spacing={1.5} alignItems="flex-start">
        {icon && (
          <Box
            sx={{
              width: 38,
              height: 38,
              flexShrink: 0,
              borderRadius: '10px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color,
              border: `1px solid ${color}`,
              bgcolor: 'transparent',
              opacity: 0.9,
              '& .MuiSvgIcon-root': { fontSize: 19 },
            }}
          >
            {icon}
          </Box>
        )}
        <Box sx={{ minWidth: 0 }}>
          <Typography
            variant="h4"
            fontWeight={800}
            lineHeight={1.1}
            className="mono"
            sx={{ fontVariantNumeric: 'tabular-nums' }}
          >
            {value}
          </Typography>
          <Typography variant="body2" fontWeight={600} sx={{ mt: 0.25 }}>
            {label}
          </Typography>
          {hint && (
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.25 }}>
              {hint}
            </Typography>
          )}
        </Box>
      </Stack>
    </Paper>
  );
}
