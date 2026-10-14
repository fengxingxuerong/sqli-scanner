// useScanActivity —— [D80] 「扫描过程全部可见」的两个视效副作用
// ① scanId 出现时把进度区滚进视口（进度区在表单下方，不滚则过程发生在屏幕外）；
// ② 运行期给 body 挂 .scanline-active（index.css 的全局扫描线）——滚到任何
//    页面位置都看得见"正在扫描"。
// 从 ScanPage 拆出：两个 useEffect + ref 使首页组件重回复杂度基线内。
// scrollIntoView 用可选调用：jsdom（单测）不实现它，但不为测试降级产品行为。
import { useEffect, useRef } from 'react';

export function useScanActivity(scanId: string | null, running: boolean) {
  const progressRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scanId) progressRef.current?.scrollIntoView?.({ behavior: 'smooth', block: 'start' });
  }, [scanId]);

  useEffect(() => {
    if (!running) return;
    document.body.classList.add('scanline-active');
    return () => { document.body.classList.remove('scanline-active'); };
  }, [running]);

  return progressRef;
}

export default useScanActivity;
