// TopNav —— 顶栏导航簇（含「扫描中」呼吸灯）
// [D80 2026-10-14] 从 TopBar 拆出：① 导航 + 激活态霓虹样式 + 运行指示灯自成一体；
// ② 原 TopBar 四项导航各写一份条件样式三元表达式（复杂度 9→14），改数据驱动后
// 全组件回到基线内。组件名/挂载点不变（TopBar 引用）。

import { Box, Button, Typography } from '@mui/material';
import { Link as RouterLink, useLocation } from 'react-router-dom';
import HomeIcon from '@mui/icons-material/Home';
import { useTranslation } from 'react-i18next';
import { useScanStore } from '../store/scanStore';

const ACTIVE_SX = {
  borderColor: 'rgba(0,212,255,0.4)',
  color: '#00d4ff',
  boxShadow: '0 0 12px rgba(0,212,255,0.15)',
};

export default function TopNav() {
  const { t } = useTranslation();
  const location = useLocation();
  // 扫描进行中：呼吸灯常驻顶栏——用户滚到任何页面都知道"还在扫"（D80）
  const scanning = useScanStore((s) => s.status) === 'running';

  const items = [
    { to: '/', key: 'nav.home', icon: <HomeIcon fontSize="small" className="mr-1" /> },
    { to: '/scan', key: 'nav.scan', icon: null },
    { to: '/history', key: 'nav.history', icon: null },
    { to: '/exploit', key: 'nav.exploit', icon: null },
  ];

  return (
    <Box className="flex gap-1 items-center">
      {scanning && (
        <Box className="flex items-center gap-1.5 mr-2 px-2" sx={{ color: '#22c55e' }} aria-label={t('topbar.scanning')}>
          <Box className="pulse-dot" sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: '#22c55e', flexShrink: 0 }} />
          <Typography variant="caption" fontWeight={700} className="mono">
            {t('topbar.scanning')}
          </Typography>
        </Box>
      )}
      {items.map((it) => {
        const active = it.to === '/' ? location.pathname === '/' : location.pathname.startsWith(it.to);
        return (
          <Button
            key={it.to}
            component={RouterLink}
            to={it.to}
            color="inherit"
            variant={active ? 'outlined' : 'text'}
            size="small"
            sx={active ? ACTIVE_SX : undefined}
          >
            {it.icon}
            {t(it.key)}
          </Button>
        );
      })}
    </Box>
  );
}
