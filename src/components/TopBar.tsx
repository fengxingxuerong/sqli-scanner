import {
  AppBar,
  Toolbar,
  Typography,
  Box,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  IconButton,
} from '@mui/material';
import BugReportIcon from '@mui/icons-material/BugReport';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import WbSunnyIcon from '@mui/icons-material/WbSunny';
import DarkModeIcon from '@mui/icons-material/DarkMode';
import SettingsBrightnessIcon from '@mui/icons-material/SettingsBrightness';
import { Link as RouterLink } from 'react-router-dom';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useThemeMode } from '../shared/themeMode';
import TopNav from './TopNav';
import HelpCenter from './HelpCenter';

// [D85] 版本角标取值：vite.config.ts define 在 build/dev 期文本替换 __APP_VERSION__；
// vitest 跑在独立 vitest.config.ts（不继承 define）下该标识符不存在 ⇒ typeof 守卫，
// vite 替换后 `typeof "1.1.1"` 恒为 string，兜底仅测试环境可见（显示 dev）。
const APP_VERSION = typeof __APP_VERSION__ !== 'undefined' ? __APP_VERSION__ : 'dev';

// 顶栏：应用标题 + 版本角标 + 导航（TopNav）+ 帮助中心入口 + 主题切换 + 语言切换
// [D85] 新增：帮助中心入口（HelpCenter 抽屉）与版本号角标（读 package.json，
// 与 version:check 门禁同源，不硬编码）。
export default function TopBar() {
  const { mode, setMode } = useThemeMode();
  const { t, i18n } = useTranslation();
  const currentLang = i18n.language;
  const [helpOpen, setHelpOpen] = useState(false);

  const switchLang = (lang: string) => {
    i18n.changeLanguage(lang);
    localStorage.setItem('sqli_lang', lang);
  };

  return (
    <AppBar
      position="static"
      elevation={0}
      sx={{
        background: mode === 'dark'
          ? 'linear-gradient(90deg, #0a0e16 0%, #111827 100%)'
          : 'linear-gradient(90deg, #0a0e16 0%, #1a1a2e 100%)',
        borderBottom: '1px solid rgba(0, 212, 255, 0.15)',
        backdropFilter: 'blur(8px)',
      }}
    >
      <Toolbar sx={{ minHeight: '56px !important' }}>
        <Box className="flex items-center gap-2 mr-6">
          <Box sx={{
            width: 32, height: 32, borderRadius: 8,
            background: 'linear-gradient(135deg, #00d4ff 0%, #8b5cf6 100%)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 12px rgba(0, 212, 255, 0.3)',
          }}>
            <BugReportIcon sx={{ fontSize: 18, color: '#0a0e16' }} />
          </Box>
          <Typography
            variant="h6"
            fontWeight={700}
            component={RouterLink}
            to="/"
            sx={{ textDecoration: 'none', color: '#e2e8f0', cursor: 'pointer', letterSpacing: '-0.01em' }}
          >
            {t('app.title')}
          </Typography>
          {/* [D85] 版本角标：等宽字体 + 青色弱化，HUD 仪表盘惯例 */}
          <Typography
            variant="caption"
            className="mono"
            sx={{ color: 'rgba(0, 212, 255, 0.55)', fontWeight: 600, userSelect: 'none' }}
          >
            v{APP_VERSION}
          </Typography>
        </Box>

        <TopNav />

        <Box className="ml-auto flex items-center gap-1">
          {/* [D85] 帮助中心入口：小白引导体系的总入口 */}
          <Tooltip title={t('topbar.helpTip')} placement="bottom" arrow>
            <IconButton
              size="small"
              aria-label={t('topbar.help')}
              onClick={() => setHelpOpen(true)}
              sx={{
                mr: 1,
                color: 'rgba(0, 212, 255, 0.8)',
                border: '1px solid rgba(0, 212, 255, 0.25)',
                '&:hover': { color: '#00d4ff', boxShadow: '0 0 10px rgba(0, 212, 255, 0.25)' },
              }}
            >
              <HelpOutlineIcon fontSize="small" />
            </IconButton>
          </Tooltip>

          {/* 语言切换 */}
          <ToggleButtonGroup
            value={currentLang}
            exclusive
            size="small"
            onChange={(_, v) => { if (v) switchLang(v); }}
            aria-label="Language switch"
          >
            <ToggleButton value="zh" aria-label="Chinese" sx={{ px: 1, minWidth: 36 }}>
              <Tooltip title="中文">
                <span>中</span>
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="en" aria-label="English" sx={{ px: 1, minWidth: 36 }}>
              <Tooltip title="English">
                <span>EN</span>
              </Tooltip>
            </ToggleButton>
          </ToggleButtonGroup>

          {/* 主题切换 */}
          <ToggleButtonGroup
            value={mode}
            exclusive
            size="small"
            onChange={(_, v) => { if (v) setMode(v); }}
            aria-label="Theme switch"
          >
            <ToggleButton value="light" aria-label="Light theme" sx={{ px: 1, minWidth: 36 }}>
              <Tooltip title="Light">
                <WbSunnyIcon fontSize="small" />
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="system" aria-label="System theme" sx={{ px: 1, minWidth: 36 }}>
              <Tooltip title="System">
                <SettingsBrightnessIcon fontSize="small" />
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="dark" aria-label="Dark theme" sx={{ px: 1, minWidth: 36 }}>
              <Tooltip title="Dark">
                <DarkModeIcon fontSize="small" />
              </Tooltip>
            </ToggleButton>
          </ToggleButtonGroup>
        </Box>
      </Toolbar>

      {/* [D85] 帮助中心抽屉 */}
      <HelpCenter open={helpOpen} onClose={() => setHelpOpen(false)} />
    </AppBar>
  );
}
