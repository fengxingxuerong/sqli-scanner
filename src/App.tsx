import { CssBaseline, ThemeProvider, createTheme, Snackbar, Alert, Button, Box, CircularProgress } from '@mui/material';
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
import { useEngineRecovery } from './hooks/useEngineRecovery';
import './i18n';

// 主题模式：浅色 / 跟随系统 / 暗色

// 首启合规声明持久化 key（勾选「已知晓」后不再弹出，参考 THEME_KEY 模式）
const DISCLAIMER_KEY = 'sqli_disclaimer';
import type { ThemeMode } from './shared/themeMode';
import { THEME_KEY, ThemeModeContext } from './shared/themeMode';
// 再导出：保持既有 import 路径不变（TopBar 等组件仍可从 App 取到主题类型/hook）
export type { ThemeMode } from './shared/themeMode';
export { useThemeMode } from './shared/themeMode';

// [D84] 引擎就绪门禁的载入态单独成组件：这段 JSX 是一次性的容器 markup，挪出后可让
// AppThemeProvider 变浅 —— 它本就在复杂度基线的豁免名单上，再长胖不合适（只许持平或变浅）。
function EngineGate({ ready, children }: { ready: boolean; children: ReactNode }) {
  if (ready) return <>{children}</>;
  return (
    <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
      <CircularProgress size={28} />
    </Box>
  );
}

// 顶层主题 Provider：动态 createTheme，主题模式持久化到 localStorage
function AppThemeProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const { engineDown, engineRecovering, restartEngine } = useEngineRecovery();
  const [mode, setModeState] = useState<ThemeMode>(() => {
    if (typeof window !== 'undefined') {
      const saved = window.localStorage.getItem(THEME_KEY);
      if (saved === 'light' || saved === 'system' || saved === 'dark') return saved;
    }
    // [D80 2026-10-14] 默认主题改暗色：视觉语言（点阵/霓虹描边/青色辉光/毛玻璃）整套按暗底
    // 设计，浅色只是附加项；原默认 light 让用户第一眼看到的是"灰色 SaaS"，赛博资产
    // （.glass/.dot-grid/.neon-border/.scanline-active）反而只在暗色下现身。
    // 已存过 sqli_theme 的历史用户不受影响（读存档优先）。
    return 'dark';
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
  // [D84] 这里还加了**渲染门禁**：引擎实连信息是异步取得的，深链路由（冷启动直达 /report/:id）
  // 在旧实现下页面比它先发请求 ⇒ 用默认 base 打 404 ⇒ 「未找到报告」（而报告其实好好的在）。
  // 现在：等引擎就绪（有界等待）后再渲染路由，覆盖所有深链页；web/测试环境立即就绪（isTauri=false 不开门禁）。
  const [engineReady, setEngineReady] = useState(!tauriBridge.isTauri);
  useEffect(() => {
    if (!tauriBridge.isTauri) return;
    let cancelled = false;
    void tauriBridge.restartEngineAndApply().finally(() => {
      if (!cancelled) setEngineReady(true); // 即使引擎最终没起来也渲染（默认 base 兜底给出可见反馈，好过停在白屏）
    });
    return () => { cancelled = true; };
  }, []);

  // [D81] 引擎生命周期 UI（自动重连 + 手动重启 + 横幅）抽至 useEngineRecovery
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
      <ThemeProvider theme={theme}>
        {/* [D84] 引擎就绪前不渲染路由：否则深链页会提前发请求、打默认 base。
            web/测试环境 engineReady 初值即 true，看不到这个加载态。 */}
        <EngineGate ready={engineReady}>{children}</EngineGate>
      </ThemeProvider>
      {/* Tauri 桌面版：引擎退出提示（D81：重连中/已失败两态） */}
      {tauriBridge.isTauri && (
        <Snackbar open={engineDown} autoHideDuration={null} anchorOrigin={{ vertical: 'top', horizontal: 'center' }}>
          <Alert
            severity={engineRecovering ? 'info' : 'error'}
            variant="filled"
            action={
              engineRecovering ? undefined : (
                <Button color="inherit" size="small" onClick={restartEngine}>{t('common.engineRestart')}</Button>
              )
            }
          >
            {engineRecovering ? t('common.engineReconnecting') : t('common.engineStopped')}
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
