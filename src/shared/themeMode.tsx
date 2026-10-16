// ============================================================================
// themeMode.tsx —— 主题模式（浅色 / 跟随系统 / 暗色）的上下文与 hook
//
// 从 App.tsx 抽离，[解循环依赖 2026-09-13]。
// 之所以单独成文件：TopBar 只需要 useThemeMode，却要从 App 导入 →
// App → router → TopBar → App 成环。共享 context 下沉后两边都依赖它，环即断。
// ============================================================================
import { createContext, useContext, useEffect } from 'react';

export type ThemeMode = 'light' | 'system' | 'dark';
export const THEME_KEY = 'sqli_theme';

interface ThemeModeContextValue {
  mode: ThemeMode;
  effectiveMode: 'light' | 'dark';
  setMode: (m: ThemeMode) => void;
}

export const ThemeModeContext = createContext<ThemeModeContextValue>({
  mode: 'light',
  effectiveMode: 'light',
  setMode: () => {},
});

// 供子组件（如 TopBar）读取/切换主题模式
export function useThemeMode() {
  return useContext(ThemeModeContext);
}

// [D86] 把生效模式写到 <html data-theme>：CSS 赛博资产（.hud-frame/.grid-floor 等）
// 按暗色语义设计，浅色变体经 [data-theme='light'] 选择器切换——CSS 无法读 MUI 主题，
// 必须由 JS 显式同步。挂在 AppThemeProvider 内（一行调用，不新增 effect 文件）。
export function useThemeDataset(effectiveMode: 'light' | 'dark') {
  useEffect(() => {
    if (typeof document !== 'undefined') {
      document.documentElement.dataset.theme = effectiveMode;
    }
  }, [effectiveMode]);
}
