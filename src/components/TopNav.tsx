// TopNav —— 顶栏导航簇（含「扫描中」呼吸灯）
// [D80 2026-10-14] 从 TopBar 拆出：① 导航 + 激活态霓虹样式 + 运行指示灯自成一体；
// ② 原 TopBar 四项导航各写一份条件样式三元表达式（复杂度 9→14），改数据驱动后
// 全组件回到基线内。组件名/挂载点不变（TopBar 引用）。
// [D107] 每项补图标 + 一句话说明（hover 可见）——「功能一眼看懂」：导航不再
// 只是一组中文词，鼠标悬停即告知该页用途；运行指示改共用 CyberLed（状态语义单一真源）。

import { Box, Button, Tooltip, Typography } from '@mui/material';
import { Link as RouterLink, useLocation } from 'react-router-dom';
import HomeIcon from '@mui/icons-material/Home';
import TravelExploreIcon from '@mui/icons-material/TravelExplore';
import HistoryIcon from '@mui/icons-material/History';
import TerminalIcon from '@mui/icons-material/Terminal';
import { useTranslation } from 'react-i18next';
import { useScanStore } from '../store/scanStore';
import CyberLed from './cyber/CyberLed';

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
    { to: '/', key: 'nav.home', icon: <HomeIcon fontSize="small" /> },
    { to: '/scan', key: 'nav.scan', icon: <TravelExploreIcon fontSize="small" /> },
    { to: '/history', key: 'nav.history', icon: <HistoryIcon fontSize="small" /> },
    { to: '/exploit', key: 'nav.exploit', icon: <TerminalIcon fontSize="small" /> },
  ];

  return (
    <Box className="flex gap-1 items-center">
      {scanning && (
        <CyberLed state="busy" label={t('topbar.scanning')} />
      )}
      {items.map((it) => {
        const active = it.to === '/' ? location.pathname === '/' : location.pathname.startsWith(it.to);
        return (
          <Tooltip key={it.to} title={t(`${it.key}Desc`)} placement="bottom" arrow>
            <Button
              component={RouterLink}
              to={it.to}
              color="inherit"
              variant={active ? 'outlined' : 'text'}
              size="small"
              startIcon={it.icon}
              sx={active ? ACTIVE_SX : { opacity: 0.82, '&:hover': { opacity: 1 } }}
            >
              <Typography component="span" variant="body2" fontWeight={active ? 700 : 500}>
                {t(it.key)}
              </Typography>
            </Button>
          </Tooltip>
        );
      })}
    </Box>
  );
}
