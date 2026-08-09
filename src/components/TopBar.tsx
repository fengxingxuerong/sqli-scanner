import {
  AppBar,
  Toolbar,
  Typography,
  Button,
  Box,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
} from '@mui/material';
import WbSunnyIcon from '@mui/icons-material/WbSunny';
import DarkModeIcon from '@mui/icons-material/DarkMode';
import SettingsBrightnessIcon from '@mui/icons-material/SettingsBrightness';
import { Link as RouterLink, useLocation } from 'react-router-dom';
import { useThemeMode } from '../App';

// 顶栏：应用标题 + 导航 + 主题切换（浅色 / 跟随系统 / 暗色）
export default function TopBar() {
  const { mode, setMode } = useThemeMode();
  const location = useLocation();

  const isActive = (path: string) =>
    path === '/' ? location.pathname === '/' || location.pathname === '/scan' : location.pathname.startsWith(path);

  return (
    <AppBar position="static" color="primary" enableColorOnDark>
      <Toolbar>
        <Typography variant="h6" fontWeight={700} className="mr-6">
          SQL 注入检测
        </Typography>

        <Box className="flex gap-1">
          <Button
            component={RouterLink}
            to="/scan"
            color="inherit"
            variant={isActive('/scan') ? 'outlined' : 'text'}
          >
            新建扫描
          </Button>
          <Button
            component={RouterLink}
            to="/history"
            color="inherit"
            variant={isActive('/history') ? 'outlined' : 'text'}
          >
            历史
          </Button>
          <Button
            component={RouterLink}
            to="/diff"
            color="inherit"
            variant={isActive('/diff') ? 'outlined' : 'text'}
          >
            对比
          </Button>
          <Button
            component={RouterLink}
            to="/exploit"
            color="inherit"
            variant={isActive('/exploit') ? 'outlined' : 'text'}
          >
            利用
          </Button>
        </Box>

        <Box className="ml-auto">
          <ToggleButtonGroup
            value={mode}
            exclusive
            size="small"
            onChange={(_, v) => {
              if (v) setMode(v);
            }}
            aria-label="主题切换"
          >
            <ToggleButton value="light" aria-label="浅色">
              <Tooltip title="浅色">
                <WbSunnyIcon fontSize="small" />
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="system" aria-label="跟随系统">
              <Tooltip title="跟随系统">
                <SettingsBrightnessIcon fontSize="small" />
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="dark" aria-label="暗色">
              <Tooltip title="暗色">
                <DarkModeIcon fontSize="small" />
              </Tooltip>
            </ToggleButton>
          </ToggleButtonGroup>
        </Box>
      </Toolbar>
    </AppBar>
  );
}
