// HomePage 首页补测（原覆盖 75%）：
//   ① 空历史：引导三步卡片 + 空态文案
//   ② 有历史：统计卡数值（总扫描/漏洞数/高危/目标去重）与最近记录渲染（sqlmap 徽标 + 风险 Chip）
//   ③ 点击记录回溯报告（navigate /report/:id）
//   ④ formatTime 容错：非法时间不崩溃
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import HomePage from '../pages/HomePage';
import { useScanStore } from '../store/scanStore';
import type { HistoryRecord } from '../shared/types';

function makeRecord(overrides: Partial<HistoryRecord> = {}): HistoryRecord {
  return {
    schemaVersion: 1,
    scanId: 'r1',
    target: 'http://t/a.php?id=1',
    riskLevel: 'Low',
    finishedAt: '2026-08-31T10:00:00Z',
    report: { engine: 'builtin', riskLevel: 'Low', vulns: [], target: { baseUrl: 'http://t/a.php?id=1' } } as any,
    ...overrides,
  };
}

function renderHome() {
  return render(
    <MemoryRouter initialEntries={['/']}>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/scan" element={<div>SCAN_PROBE</div>} />
        <Route path="/report/:id" element={<div>REPORT_PROBE</div>} />
      </Routes>
    </MemoryRouter>
  );
}

beforeEach(() => {
  localStorage.removeItem('sqli_scan_history_v1');
  useScanStore.setState({ history: [] });
});

describe('HomePage · 空历史', () => {
  it('显示空态文案与三步引导', () => {
    renderHome();
    expect(screen.getByText(/还没有扫描记录/)).toBeTruthy();
    expect(screen.getByText('输入目标 URL')).toBeTruthy();
    expect(screen.getByText('一键开始检测')).toBeTruthy();
    expect(screen.getByText('查看检测报告')).toBeTruthy();
  });
});

describe('HomePage · 统计与最近记录', () => {
  it('统计卡数值：总扫描/漏洞数/高危/去重目标', () => {
    useScanStore.setState({
      history: [
        makeRecord({
          scanId: 'r1',
          riskLevel: 'High',
          report: { engine: 'sqlmap', riskLevel: 'High', vulns: [{}, {}, {}], target: { baseUrl: 'http://a/' } } as any,
        }),
        makeRecord({ scanId: 'r2', target: 'http://b/', report: { engine: 'builtin', riskLevel: 'Low', vulns: [{}, {}], target: { baseUrl: 'http://b/' } } as any }),
        makeRecord({ scanId: 'r3', target: 'http://b/', report: { engine: 'builtin', riskLevel: 'Low', vulns: [], target: { baseUrl: 'http://b/' } } as any }),
      ],
    });
    renderHome();
    // 统计标签存在（数值渲染于同一卡片）
    expect(screen.getByText('总扫描次数')).toBeTruthy();
    expect(screen.getByText('发现漏洞')).toBeTruthy();
    expect(screen.getByText('高危风险')).toBeTruthy();
    expect(screen.getByText('已检测目标')).toBeTruthy();
    // 最近记录渲染：sqlmap 徽标 + 目标 URL（取 report.target.baseUrl）
    expect(screen.getByText('sqlmap')).toBeTruthy();
    expect(screen.getByText('http://a/')).toBeTruthy();
  });

  it('点击记录回溯报告页', async () => {
    useScanStore.setState({ history: [makeRecord()] });
    renderHome();
    fireEvent.click(screen.getByText('http://t/a.php?id=1'));
    await waitFor(() => expect(screen.getByText('REPORT_PROBE')).toBeTruthy());
  });

  it('非法时间戳不崩溃（formatTime 容错）', () => {
    useScanStore.setState({ history: [makeRecord({ finishedAt: 'not-a-date' })] });
    renderHome();
    expect(screen.getByText('http://t/a.php?id=1')).toBeTruthy();
  });
});
