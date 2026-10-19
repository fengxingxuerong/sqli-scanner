// ============================================================================
// PageHeader —— 统一页头（D107 桌面端 UI 全面优化）
//
// 「功能一眼看懂」的落地件：图标 + 标题 + 一句话说明（这页能干什么）+ 右侧操作。
// 此前四个页面四种标题写法（h4 / h5 / h6 混用、副标题有无不一），
// 用户切换页面时缺少稳定的位置感。统一后页头是页面的「身份证」。
// ============================================================================
import type { ReactNode } from 'react';
import { Box, Stack, Typography } from '@mui/material';

interface PageHeaderProps {
  /** 标题左侧图标 */
  icon?: ReactNode;
  title: string;
  /** 一句话说明：这个页面用来做什么 */
  desc?: string;
  /** 右侧操作区 */
  actions?: ReactNode;
}

export default function PageHeader({ icon, title, desc, actions }: PageHeaderProps) {
  return (
    <Stack
      direction="row"
      alignItems={{ xs: 'flex-start', sm: 'center' }}
      justifyContent="space-between"
      spacing={2}
      className="mb-4"
      sx={{ position: 'relative', pb: 2 }}
    >
      <Stack direction="row" spacing={1.5} alignItems="center" sx={{ minWidth: 0 }}>
        {icon && (
          <Box
            sx={{
              width: 40,
              height: 40,
              flexShrink: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: '10px',
              color: 'var(--cy-cyan)',
              border: '1px solid var(--cy-line-strong)',
              bgcolor: 'var(--cy-cyan-faint)',
              '& .MuiSvgIcon-root': { fontSize: 21 },
            }}
          >
            {icon}
          </Box>
        )}
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="h5" fontWeight={800} sx={{ letterSpacing: '-0.02em', lineHeight: 1.2 }}>
            {title}
          </Typography>
          {desc && (
            <Typography variant="body2" color="text.secondary" className="mt-0.5">
              {desc}
            </Typography>
          )}
        </Box>
      </Stack>
      {actions && (
        <Stack direction="row" spacing={1} alignItems="center" flexShrink={0}>
          {actions}
        </Stack>
      )}
      {/* 底部霓虹分隔：页头与内容区的分界 */}
      <Box
        aria-hidden="true"
        sx={{
          position: 'absolute',
          left: 0,
          right: 0,
          bottom: 0,
          height: '1px',
          background:
            'linear-gradient(90deg, var(--cy-line-strong) 0%, var(--cy-line) 30%, transparent 100%)',
        }}
      />
    </Stack>
  );
}
