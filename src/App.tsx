import { CssBaseline, ThemeProvider, createTheme, Snackbar, Alert, Button } from '@mui/material';
import {
  useState,
  useEffect,
  useCallback,
  Suspense,
} from 'react';
import type { ReactNode } from 'react';
import { RouterProvider } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import router, { PageFallback } from './router';
import DisclaimerDialog from './components/DisclaimerDialog';
import { tauriBridge } from './shared/tauriBridge';
import { setApiBase, setApiToken } from './shared/apiClient';
import './i18n';

// 主题模式：浅色 / 跟随系统 / 暗色

// 首启合规声明持久化 key（勾选「已知晓」后不再弹出，参考 THEME_KEY 模式）
const DISCLAIMER_KEY = 'sqli_disclaimer';
import type { ThemeMode } from './shared/themeMode';
import { THEME_KEY, ThemeModeContext } from './shared/themeMode';
// 再导出：保持既有 import 路径不变（TopBar 等组件仍可从 App 取到主题类型/hook）
export type { ThemeMode } from './shared/themeMode';
export { useThemeMode } from './shared/themeMode';

// 顶层主题 Provider：动态 createTheme，主题模式持久化到 localStorage
function AppThemeProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
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

  // [A3 2026-09-17] 桌面版：向 Rust 询问 sidecar 实际端口与一次性 token。
  // 引擎不再固定 4567（端口被占时随机），且带鉴权 token，前端必须按实况连接。
  useEffect(() => {
    if (!tauriBridge.isTauri) return;
    let cancelled = false;
    (async () => {
      const info = await tauriBridge.getEngineInfo();
      if (cancelled || !info) return;
      setApiBase(`http://127.0.0.1:${info.port}/api`);
      if (info.token) setApiToken(info.token);
    })();
    return () => { cancelled = true; };
  }, []);

  // Tauri 桌面版：监听引擎崩溃/退出，Snackbar 提示用户可重启
  const [engineDown, setEngineDown] = useState(false);
  useEffect(() => {
    if (!tauriBridge.isTauri) return;
    const unlisten = tauriBridge.onEngineExit(() => {
      setEngineDown(true);
    });
    return () => { if (unlisten) unlisten(); };
  }, []);

  const restartEngine = () => {
    setEngineDown(false);
    tauriBridge.startEngine().catch(() => undefined);
  };

  const effectiveMode: 'light' | 'dark' =
    mode === 'system' ? (systemDark ? 'dark' : 'light') : mode;

  const setMode = useCallback((m: ThemeMode) => setModeState(m), []);

  const theme = createTheme({
    palette: {
      mode: effectiveMode,
      primary: { main: '#00d4ff', light: '#33dfff', dark: '#0099cc', contrastText: '#0a0e16' },
      secondary: { main: '#8b5cf6', light: '#a78bfa', dark: '#6d28d9' },
      error: { main: '#ef4444' },
      warning: { main: '#fbbf24' },
      success: { main: '#22c55e' },
      info: { main: '#00d4ff' },
      ...(effectiveMode === 'dark'
        ? {
            background: { default: '#0a0e16', paper: '#111827' },
            text: { primary: '#e2e8f0', secondary: '#64748b' },
          }
        : {
            background: { default: '#f0f4f8', paper: '#ffffff' },
            text: { primary: '#0f172a', secondary: '#475569' },
          }),
    },
    typography: {
      fontFamily: '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif',
      h3: { fontWeight: 800, letterSpacing: '-0.03em' },
      h4: { fontWeight: 800, letterSpacing: '-0.02em' },
      h5: { fontWeight: 700, letterSpacing: '-0.01em' },
      h6: { fontWeight: 700 },
      subtitle1: { fontWeight: 700 },
      subtitle2: { fontWeight: 600 },
      button: { fontWeight: 600 },
    },
    shape: { borderRadius: 10 },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            scrollbarColor: effectiveMode === 'dark' ? '#1e293b #0a0e16' : '#cbd5e1 #f0f4f8',
            '&::-webkit-scrollbar': { width: '8px', height: '8px' },
            '&::-webkit-scrollbar-thumb': {
              borderRadius: 4,
              background: effectiveMode === 'dark' ? '#1e293b' : '#cbd5e1',
            },
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            borderRadius: 12,
            boxShadow: effectiveMode === 'dark'
              ? '0 0 0 1px rgba(0, 212, 255, 0.06), 0 4px 24px rgba(0,0,0,0.4)'
              : '0 0 0 1px rgba(0,0,0,0.04), 0 2px 8px rgba(0,0,0,0.04)',
            ...(effectiveMode === 'dark' && {
              border: '1px solid rgba(0, 212, 255, 0.08)',
              backgroundColor: 'rgba(17, 24, 39, 0.8)',
              backdropFilter: 'blur(8px)',
            }),
            transition: 'border-color 0.2s, box-shadow 0.2s',
            '&:hover': effectiveMode === 'dark'
              ? { borderColor: 'rgba(0, 212, 255, 0.25)', boxShadow: '0 0 0 1px rgba(0, 212, 255, 0.15), 0 4px 24px rgba(0,0,0,0.5)' }
              : { boxShadow: '0 0 0 1px rgba(0,0,0,0.08), 0 4px 16px rgba(0,0,0,0.06)' },
          },
        },
      },
      MuiPaper: { styleOverrides: { root: { borderRadius: 12 } } },
      MuiButton: {
        styleOverrides: {
          root: { borderRadius: 8, textTransform: 'none', fontWeight: 600 },
          containedPrimary: {
            background: 'linear-gradient(135deg, #00d4ff 0%, #8b5cf6 100%)',
            color: '#0a0e16',
            boxShadow: '0 0 20px rgba(0, 212, 255, 0.25)',
            '&:hover': {
              background: 'linear-gradient(135deg, #33dfff 0%, #a78bfa 100%)',
              boxShadow: '0 0 30px rgba(0, 212, 255, 0.4)',
            },
          },
          outlinedPrimary: {
            borderColor: effectiveMode === 'dark' ? 'rgba(0, 212, 255, 0.3)' : 'rgba(0, 212, 255, 0.5)',
            '&:hover': {
              borderColor: '#00d4ff',
              bgcolor: effectiveMode === 'dark' ? 'rgba(0, 212, 255, 0.08)' : 'rgba(0, 212, 255, 0.04)',
            },
          },
        },
      },
      MuiChip: { styleOverrides: { root: { borderRadius: 6, fontWeight: 500 } } },
      MuiLinearProgress: {
        styleOverrides: {
          root: { borderRadius: 4, height: 6, backgroundColor: effectiveMode === 'dark' ? 'rgba(0, 212, 255, 0.1)' : undefined },
          bar: { borderRadius: 4, background: 'linear-gradient(90deg, #00d4ff, #8b5cf6)' },
        },
      },
      MuiTextField: {
        styleOverrides: {
          root: {
            '& .MuiOutlinedInput-root': effectiveMode === 'dark' ? {
              '& fieldset': { borderColor: 'rgba(0, 212, 255, 0.15)' },
              '&:hover fieldset': { borderColor: 'rgba(0, 212, 255, 0.3)' },
              '&.Mui-focused fieldset': { borderColor: '#00d4ff' },
            } : undefined,
          },
        },
      },
      MuiAppBar: { styleOverrides: { root: { boxShadow: 'none' } } },
    },
  });

  return (
    <ThemeModeContext.Provider value={{ mode, effectiveMode, setMode }}>
      <ThemeProvider theme={theme}>{children}</ThemeProvider>
      {/* Tauri 桌面版：引擎退出提示 */}
      {tauriBridge.isTauri && (
        <Snackbar open={engineDown} autoHideDuration={null} anchorOrigin={{ vertical: 'top', horizontal: 'center' }}>
          <Alert severity="error" variant="filled" action={
            <Button color="inherit" size="small" onClick={restartEngine}>{t('common.engineRestart')}</Button>
          }>
            {t('common.engineStopped')}
          </Alert>
        </Snackbar>
      )}
    </ThemeModeContext.Provider>
  );
}

// 应用根组件：主题 + 一次性免责声明门禁 + 顶栏 + 路由出口。
// 未接受授权声明（localStorage['sqli_disclaimer'] !== '1'）时不渲染任何业务内容。
export default function App() {
  const [disclaimerAccepted, setDisclaimerAccepted] = useState<boolean>(() => {
    if (typeof window !== 'undefined') {
      return window.localStorage.getItem(DISCLAIMER_KEY) === '1';
    }
    return false;
  });

  // 勾选「已知晓」后写入 localStorage，此后不再弹出
  const acceptDisclaimer = useCallback(() => {
    if (typeof window !== 'undefined') window.localStorage.setItem(DISCLAIMER_KEY, '1');
    setDisclaimerAccepted(true);
  }, []);

  return (
    <AppThemeProvider>
      <CssBaseline />
      <DisclaimerDialog open={!disclaimerAccepted} onAccept={acceptDisclaimer} />
      {disclaimerAccepted && (
        // 外层兜底 Suspense：真实页面懒加载由 router.tsx 内层 Suspense（包裹 Outlet）
        // 承接，顶栏不受影响；此处仅兜底「Layout 之上未来可能出现的挂起节点」，
        // 正常路由切换时不会触发，不会造成整页闪白。
        <Suspense fallback={<PageFallback />}>
          <RouterProvider router={router} />
        </Suspense>
      )}
    </AppThemeProvider>
  );
}
