// 首页：总览仪表盘 —— 一眼看清「能做什么 / 做过什么 / 现在多危险」
//
// 版式（自上而下）：
//   Hero     —— 一句话定位 + 主 CTA（开始扫描），赛博玻璃风（D79 拆至 ../components/HomeHero）
//   Guide    —— 「三步上手」常驻引导：填 URL → 点扫描 → 看报告
//   Stats    —— 四个数：扫过多少次 / 挖出多少洞 / 多少高危 / 覆盖多少目标
//   Recent   —— 最近 5 次扫描，整行可点回溯报告
//
// [D107] 变更要点：
//   · 三步引导由「仅空历史时显示」改为常驻 —— 有记录后新手就看不到用法，是引导失效；
//   · 统计卡换 CyberStat（数字等宽 + 口径注解），外形与报告页统一；
//   · 最近记录补「查看报告」按钮 —— 整行可点这件事不写出来没人知道；
//   · 移除本页重复的 .dot-grid（Layout 已全局挂载，重复会叠两层点阵）。
//
// 说明：store 暴露的是 history 状态字段（useScanStore((s) => s.history)），
//      与 HistoryPage 使用方式一致，返回 HistoryRecord[]。

import { Container, Stack } from '@mui/material';
import { useScanStore } from '../store/scanStore';
import HomeHero from '../components/HomeHero';
import HomeGuide from '../components/home/HomeGuide';
import HomeStats from '../components/home/HomeStats';
import HomeRecent from '../components/home/HomeRecent';

// 首页默认导出组件
export default function HomePage() {
  const history = useScanStore((s) => s.history);

  const recent = history.slice(0, 5); // 最近 5 次

  return (
    <Container maxWidth="lg" className="py-6">
      <Stack className="animate-in" spacing={0}>
        {/* ── Hero：赛博玻璃风 ── */}
        <HomeHero />

        {/* ── 三步上手（常驻）── */}
        <HomeGuide />

        {/* ── 快速统计 ── */}
        <HomeStats history={history} />

        {/* ── 最近扫描（5 条）── */}
        <HomeRecent rows={recent} hasHistory={history.length > 0} />
      </Stack>
    </Container>
  );
}
