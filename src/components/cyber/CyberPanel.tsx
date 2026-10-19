// ============================================================================
// CyberPanel —— 赛博 HUD 面板容器（D107 桌面端 UI 全面优化）
//
// 统一各页面的「区块外形」：切角 + 玻璃底 + 顶部霓虹扫描线 + HUD 四角。
// 之前每个页面各写一份 Paper/Card 的 sx（边框色 / 圆角 / 阴影内联硬编码），
// 既漂移又重复；收敛到本组件后外形只在一处定义，浅色变体由
// cyber.css 的 [data-theme='light'] 兜住，不需要调用方判主题。
// ============================================================================
import type { ReactNode } from 'react';
import { Box, Paper, Stack, Typography } from '@mui/material';

export type CyberTone = 'default' | 'danger' | 'success' | 'warn';

/** 面板语义色 → 描边/标题取色（暗色下带辉光，浅色下为同色相深变体） */
const TONE_VAR: Record<CyberTone, string> = {
  default: 'var(--cy-cyan)',
  danger: 'var(--cy-magenta)',
  success: 'var(--cy-lime)',
  warn: 'var(--cy-amber)',
};

interface CyberPanelProps {
  /** 区块标题；不传则只渲染内容区（无头部） */
  title?: string;
  /** 标题左侧图标（MUI 图标元素） */
  icon?: ReactNode;
  /** 标题右侧操作区（按钮 / 提示） */
  actions?: ReactNode;
  /** 标题下的一句话说明 —— 「这块是干什么的」 */
  desc?: string;
  tone?: CyberTone;
  /** 是否绘制顶部霓虹扫描线（HUD 通电感），默认开 */
  scan?: boolean;
  children?: ReactNode;
  /** 内容区内边距档位：紧凑 / 常规 */
  dense?: boolean;
  /** 追加到根节点的类名（用于外层间距） */
  className?: string;
}

export default function CyberPanel({
  title,
  icon,
  actions,
  desc,
  tone = 'default',
  scan = true,
  children,
  dense = false,
  className,
}: CyberPanelProps) {
  const accent = TONE_VAR[tone];
  const hasHeader = Boolean(title || actions);
  const rootClass = [scan ? 'cyber-panel cyber-panel--scan' : 'cyber-panel', 'cyber-clip', className]
    .filter(Boolean)
    .join(' ');
  return (
    <Paper
      variant="outlined"
      className={rootClass}
      sx={{
        borderRadius: 0,
        overflow: 'hidden',
        borderColor: 'var(--cy-line)',
        ...(tone !== 'default' && { borderLeft: `2px solid ${accent}` }),
      }}
    >
      {hasHeader && (
        <Box
          className="flex items-center gap-2 flex-wrap"
          sx={{ px: dense ? 2 : 2.5, py: 1.25, borderBottom: '1px solid var(--cy-line)' }}
        >
          {icon && (
            <Box sx={{ display: 'flex', color: accent, '& .MuiSvgIcon-root': { fontSize: 18 } }}>
              {icon}
            </Box>
          )}
          <Box sx={{ minWidth: 0 }}>
            {title && (
              <Typography variant="subtitle2" fontWeight={700} className="cyber-tag" sx={{ color: accent }}>
                {title}
              </Typography>
            )}
            {desc && (
              <Typography variant="caption" color="text.secondary">
                {desc}
              </Typography>
            )}
          </Box>
          {actions && (
            <Stack direction="row" spacing={1} alignItems="center" sx={{ ml: 'auto' }}>
              {actions}
            </Stack>
          )}
        </Box>
      )}
      <Box sx={{ p: dense ? 2 : 2.5 }}>{children}</Box>
    </Paper>
  );
}
