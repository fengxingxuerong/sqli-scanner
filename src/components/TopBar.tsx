import {
  AppBar,
  Toolbar,
  Typography,
  Box,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
} from '@mui/material';
import BugReportIcon from '@mui/icons-material/BugReport';
import WbSunnyIcon from '@mui/icons-material/WbSunny';
import DarkModeIcon from '@mui/icons-material/DarkMode';
import SettingsBrightnessIcon from '@mui/icons-material/SettingsBrightness';
import { Link as RouterLink } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useThemeMode } from '../shared/themeMode';
import TopNav from './TopNav';

// 顶栏：应用标题 + 导航（TopNav）+ 主题切换 + 语言切换
export default function TopBar() {
  const { mode, setMode } = useThemeMode();
  const { t, i18n } = useTranslation();
  const currentLang = i18n.language;

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
        </Box>

        <TopNav />

        <Box className="ml-auto flex items-center gap-1">
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
    </AppBar>
  );
}
