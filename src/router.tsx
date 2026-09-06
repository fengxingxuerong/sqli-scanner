import { lazy, Suspense } from 'react';
import { useTranslation } from 'react-i18next';
import { Box, CircularProgress } from '@mui/material';
import { createBrowserRouter, Outlet } from 'react-router-dom';
import TopBar from './components/TopBar';
import ErrorBoundary from './components/ErrorBoundary';

// ── 页面级懒加载（主 chunk 641KB / 205KB gzip 拆分）────────────────────────
// 四个页面（及其组件树：ScanConfigPanel/SqlmapOptions/ProgressView/TargetForm/
// WafTamperPanel、VulnList/VulnDetail/DbTree/ReportExport/PayloadViewer/
// BlindTraceTimeline 等）原本被同步打包进主 chunk，是 Vite 构建 chunk 过大
// 警告的主因。改为 React.lazy + 动态 import 后，Vite 按页面拆出独立 chunk，
// 首屏仅需 TopBar + 路由壳，进入具体页面时才加载对应 chunk。
const HomePage = lazy(() => import('./pages/HomePage'));
const ScanPage = lazy(() => import('./pages/ScanPage'));
const ReportPage = lazy(() => import('./pages/ReportPage'));
const HistoryPage = lazy(() => import('./pages/HistoryPage'));
const ExploitPage = lazy(() => import('./pages/ExploitPage'));

// 页面区加载占位：仅页面区域显示加载态，顶栏/导航保持可见不闪烁
export function PageFallback() {
  const { t } = useTranslation();
  return (
    <Box
      sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', py: 10 }}
      role="status"
      aria-label={t('common.pageLoading')}
    >
      <CircularProgress size={28} />
    </Box>
  );
}

// 布局路由：顶栏（含导航与主题切换）与路由出口同处 Router 上下文。
// 关键：TopBar 使用 useLocation，必须位于 RouterProvider 内部，否则会抛
// "useLocation() may be used only in the context of a <Router>" 导致整页白屏。
// Suspense 包裹 Outlet：懒加载页面 chunk 就绪前仅页面区显示占位（PageFallback），
// 顶栏与导航不参与挂起，避免整页闪白。
// ErrorBoundary 包裹页面出口：组件渲染异常显示降级 UI，防白屏。
const Layout = () => {
  const { t } = useTranslation();
  return (
    <>
      <a href="#main-content" className="skip-link">{t('common.skipToContent')}</a>
      <TopBar />
      <ErrorBoundary>
        <Suspense fallback={<PageFallback />}>
          <div id="main-content">
            <Outlet />
          </div>
        </Suspense>
      </ErrorBoundary>
    </>
  );
};

// 路由表：扫描 / 报告 / 历史 / 利用（统一包在 Layout 内）
// 注意：路由结构与导出保持不变（`router` 具名导出 + default 导出），
// 懒加载对路由消费者透明，不影响 src/tests 中直接渲染页面/组件的测试。
export const router = createBrowserRouter([
  {
    element: <Layout />,
    children: [
      { path: '/', element: <HomePage /> },
      { path: '/scan', element: <ScanPage /> },
      { path: '/report/:id', element: <ReportPage /> },
      { path: '/history', element: <HistoryPage /> },
      { path: '/exploit', element: <ExploitPage /> },
    ],
  },
]);

export default router;
