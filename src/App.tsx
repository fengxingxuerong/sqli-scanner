import { CssBaseline, ThemeProvider, createTheme } from '@mui/material';
import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
} from 'react';
import type { ReactNode } from 'react';
import { RouterProvider } from 'react-router-dom';
import router from './router';

// 主题模式：浅色 / 跟随系统 / 暗色
export type ThemeMode = 'light' | 'system' | 'dark';
const THEME_KEY = 'sqli_theme';

interface ThemeModeContextValue {
  mode: ThemeMode;
  effectiveMode: 'light' | 'dark';
  setMode: (m: ThemeMode) => void;
}

const ThemeModeContext = createContext<ThemeModeContextValue>({
  mode: 'light',
  effectiveMode: 'light',
  setMode: () => {},
});

// 供子组件（如 TopBar）读取/切换主题模式
export function useThemeMode() {
  return useContext(ThemeModeContext);
}

// 顶层主题 Provider：动态 createTheme，主题模式持久化到 localStorage
function AppThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(() => {
    if (typeof window !== 'undefined') {
      const saved = window.localStorage.getItem(THEME_KEY);
      if (saved === 'light' || saved === 'system' || saved === 'dark') return saved;
    }
    return 'light';
  });
  const [systemDark, setSystemDark] = useState(false);

  // 监听系统配色变化（仅「跟随系统」模式需要）
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const update = () => setSystemDark(mq.matches);
    update();
    mq.addEventListener('change', update);
    return () => mq.removeEventListener('change', update);
  }, []);

  // 持久化主题模式
  useEffect(() => {
    if (typeof window !== 'undefined') window.localStorage.setItem(THEME_KEY, mode);
  }, [mode]);

  const effectiveMode: 'light' | 'dark' =
    mode === 'system' ? (systemDark ? 'dark' : 'light') : mode;

  const setMode = useCallback((m: ThemeMode) => setModeState(m), []);

  const theme = createTheme({
    palette: {
      mode: effectiveMode,
      primary: { main: '#1976d2' },
      secondary: { main: '#9c27b0' },
    },
    typography: {
      fontFamily:
        '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif',
    },
  });

  return (
    <ThemeModeContext.Provider value={{ mode, effectiveMode, setMode }}>
      <ThemeProvider theme={theme}>{children}</ThemeProvider>
    </ThemeModeContext.Provider>
  );
}

// 应用根组件：主题 + 顶栏 + 路由出口
export default function App() {
  return (
    <AppThemeProvider>
      <CssBaseline />
      <RouterProvider router={router} />
    </AppThemeProvider>
  );
}
