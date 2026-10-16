// InfoHint —— 通用「?」信息提示（D85 小白引导体系的基础组件）
// 两种形态：
//  · 缺省（短说明）：hover / 聚焦即显 Tooltip，用于配置项一句话解释；
//  · rich（长说明）：点击展开 Popover，用于分区说明、判读指南等可换行长文。
// 视觉：青色描边圆形按钮 + hover 辉光，暗色赛博语言（与 .neon-border 同源）。
// 可达性：IconButton 原生 button，可 Tab 聚焦、Enter 触发；aria-label 取说明全文，
// 屏幕阅读器不依赖视觉图标。

import { useState } from 'react';
import { IconButton, Popover, Tooltip, Typography } from '@mui/material';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';

interface InfoHintProps {
  /** 提示文案。短形态为单行短句；rich 形态为可换行的长说明 */
  text: string;
  /** true = 点击展开 Popover（长说明）；缺省 = hover Tooltip（短说明） */
  rich?: boolean;
  /** rich 形态弹层标题；缺省不显示标题行 */
  title?: string;
}

export default function InfoHint({ text, rich = false, title }: InfoHintProps) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);

  const button = (
    <IconButton
      size="small"
      aria-label={text}
      onClick={rich ? (e) => setAnchor(e.currentTarget) : undefined}
      sx={{
        p: 0.25,
        ml: 0.5,
        color: 'rgba(0, 212, 255, 0.7)',
        border: '1px solid rgba(0, 212, 255, 0.25)',
        backgroundColor: 'rgba(0, 212, 255, 0.06)',
        '&:hover': {
          color: '#00d4ff',
          backgroundColor: 'rgba(0, 212, 255, 0.14)',
          boxShadow: '0 0 10px rgba(0, 212, 255, 0.25)',
        },
        '& .MuiSvgIcon-root': { fontSize: 15 },
      }}
    >
      <HelpOutlineIcon />
    </IconButton>
  );

  if (!rich) {
    return (
      <Tooltip title={text} placement="top" arrow>
        {button}
      </Tooltip>
    );
  }

  return (
    <>
      {button}
      <Popover
        open={anchor !== null}
        anchorEl={anchor}
        onClose={() => setAnchor(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
        transformOrigin={{ vertical: 'top', horizontal: 'left' }}
        slotProps={{
          paper: {
            sx: {
              maxWidth: 380,
              p: 2,
              bgcolor: 'rgba(17, 24, 39, 0.95)',
              border: '1px solid rgba(0, 212, 255, 0.2)',
              backdropFilter: 'blur(12px)',
            },
          },
        }}
      >
        {title && (
          <Typography variant="subtitle2" fontWeight={700} sx={{ color: '#00d4ff', mb: 0.5 }}>
            {title}
          </Typography>
        )}
        <Typography variant="body2" sx={{ lineHeight: 1.7 }}>
          {text}
        </Typography>
      </Popover>
    </>
  );
}
