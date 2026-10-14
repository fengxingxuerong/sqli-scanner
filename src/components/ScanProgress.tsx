// ScanProgress —— 扫描进度面板外壳（ref 转发 + 运行态霓虹描边）
// [D80 2026-10-14] 从 ScanPage 拆出：进度区是自含的「运行态展示」职责。
// 刻意的薄壳设计：面板**内容**（进度条/状态 Chip/统计/直播控制台）全部留在
// ProgressView 单一真源——中途曾把进度条+Chic 搬进来，与 ProgressView 原有
// 渲染构成双重渲染（104 token 克隆被 duplication 门禁实锤、两份进度条同时出现），
// 故收敛为「外壳归外壳、内容归内容」：本组件只拥有 Paper 容器与运行态样式。
// ref 转发给 Paper 根：ScanPage 的 useScanActivity 要把它滚进视口。

import { Paper } from '@mui/material';
import { forwardRef } from 'react';
import ProgressView from './ProgressView';

interface Props {
  running: boolean;
}

const ScanProgress = forwardRef<HTMLDivElement, Props>(function ScanProgress({ running }, ref) {
  return (
    <Paper
      ref={ref}
      variant="outlined"
      className="mt-4 p-4"
      sx={{
        borderRadius: 3,
        borderColor: running ? 'primary.main' : undefined,
        boxShadow: running ? '0 0 24px rgba(0, 212, 255, 0.12)' : undefined,
      }}
    >
      <ProgressView />
    </Paper>
  );
});

export default ScanProgress;
