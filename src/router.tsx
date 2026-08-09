import { createBrowserRouter, Outlet } from 'react-router-dom';
import ScanPage from './pages/ScanPage';
import ReportPage from './pages/ReportPage';
import HistoryPage from './pages/HistoryPage';
import ExploitPage from './pages/ExploitPage';
import ReportDiffPage from './pages/ReportDiffPage';
import TopBar from './components/TopBar';

// 布局路由：顶栏（含导航与主题切换）与路由出口同处 Router 上下文。
// 关键：TopBar 使用 useLocation，必须位于 RouterProvider 内部，否则会抛
// "useLocation() may be used only in the context of a <Router>" 导致整页白屏。
const Layout = () => (
  <>
    <TopBar />
    <Outlet />
  </>
);

// 路由表：扫描 / 报告 / 历史（统一包在 Layout 内）
export const router = createBrowserRouter([
  {
    element: <Layout />,
    children: [
      { path: '/', element: <ScanPage /> },
      { path: '/scan', element: <ScanPage /> },
      { path: '/report/:id', element: <ReportPage /> },
      { path: '/history', element: <HistoryPage /> },
      { path: '/diff', element: <ReportDiffPage /> },
      { path: '/exploit', element: <ExploitPage /> },
    ],
  },
]);

export default router;
