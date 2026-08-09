import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import ProgressView, { deriveProgress, formatDuration, estimateRemaining } from '../components/ProgressView';
import { useScanStore } from '../store/scanStore';
import type { ScanEvent } from '../shared/types';

describe('ProgressView 组件', () => {
  it('无事件时显示占位提示', () => {
    useScanStore.getState().reset();
    render(<ProgressView />);
    expect(screen.getByText('暂无事件，开始扫描后这里会实时显示进度')).toBeTruthy();
  });

  it('渲染从 store 读取的事件流', () => {
    useScanStore.getState().reset();
    useScanStore.getState().addEvent({ type: 'detect', ts: '12:00', payload: 'vuln found' });
    render(<ProgressView />);
    expect(screen.getByText(/vuln found/)).toBeTruthy();
  });

  it('展示当前状态标签', () => {
    useScanStore.getState().reset();
    useScanStore.getState().setStatus('running');
    render(<ProgressView />);
    // 任务卡与实时进度区各有一个状态 Chip，故用 getAllByText 校验至少出现一次
    expect(screen.getAllByText('扫描中').length).toBeGreaterThanOrEqual(1);
    useScanStore.getState().reset();
  });
});

describe('deriveProgress 阶段推导', () => {
  it('pending → 0% 待开始', () => {
    expect(deriveProgress('pending', [])).toEqual({ percent: 0, stage: '待开始' });
  });
  it('completed/stopped/error → 100% 对应阶段文案', () => {
    expect(deriveProgress('completed', []).stage).toBe('已完成');
    expect(deriveProgress('stopped', []).stage).toBe('已停止');
    expect(deriveProgress('error', []).stage).toBe('出错');
  });
  it('running 按事件类型推断当前阶段', () => {
    const ev = (t: string): ScanEvent => ({ type: t as ScanEvent['type'], ts: '1', payload: null });
    expect(deriveProgress('running', []).stage).toBe('初始化');
    expect(deriveProgress('running', [ev('point_discovered')]).stage).toBe('探测注入点');
    expect(deriveProgress('running', [ev('second_order_discovery')]).stage).toBe('二阶发现');
    expect(deriveProgress('running', [ev('detection_found')]).stage).toBe('确认漏洞');
    expect(deriveProgress('running', [ev('sqlmap_vuln')]).stage).toBe('确认漏洞');
  });
});

describe('formatDuration / estimateRemaining（耗时与预计剩余）', () => {
  it('formatDuration：0/负/NaN → 0s', () => {
    expect(formatDuration(0)).toBe('0s');
    expect(formatDuration(-5)).toBe('0s');
    expect(formatDuration(NaN)).toBe('0s');
  });
  it('formatDuration：秒 / 分秒 / 时分', () => {
    expect(formatDuration(45000)).toBe('45s');
    expect(formatDuration(125000)).toBe('2m 5s');
    expect(formatDuration(3725000)).toBe('1h 2m');
  });
  it('estimateRemaining：不足 2 事件 → remainingMs null', () => {
    expect(
      estimateRemaining([{ type: 'x', scanId: 's', ts: '1', payload: null } as ScanEvent], 50).remainingMs,
    ).toBeNull();
  });
  it('estimateRemaining：percent>=100 → remainingMs null', () => {
    const evs = [
      { type: 'x', scanId: 's', ts: new Date(0).toISOString(), payload: null },
      { type: 'x', scanId: 's', ts: new Date(10000).toISOString(), payload: null },
    ] as ScanEvent[];
    expect(estimateRemaining(evs, 100).remainingMs).toBeNull();
  });
  it('estimateRemaining：已用 10s 占 20% → 剩余 40s', () => {
    const evs = [
      { type: 'x', scanId: 's', ts: new Date(0).toISOString(), payload: null },
      { type: 'x', scanId: 's', ts: new Date(10000).toISOString(), payload: null },
    ] as ScanEvent[];
    const r = estimateRemaining(evs, 20);
    expect(r.elapsedMs).toBe(10000);
    expect(r.remainingMs).toBe(40000);
  });
  it('estimateRemaining：非法 ts → remainingMs null', () => {
    const evs = [
      { type: 'x', scanId: 's', ts: 'bad', payload: null },
      { type: 'x', scanId: 's', ts: 'worse', payload: null },
    ] as ScanEvent[];
    expect(estimateRemaining(evs, 20).remainingMs).toBeNull();
  });
});

describe('ProgressView 运行时展示耗时与预计剩余', () => {
  it('running 且有 2+ 事件时渲染「已耗时」与「预计剩余（估算）」', () => {
    useScanStore.getState().reset();
    useScanStore.setState({
      status: 'running',
      events: [
        { type: 'point_discovered', scanId: 's', ts: new Date(0).toISOString(), payload: null },
        { type: 'point_discovered', scanId: 's', ts: new Date(10000).toISOString(), payload: null },
      ] as ScanEvent[],
    });
    render(<ProgressView />);
    expect(screen.getByText('已耗时')).toBeTruthy();
    expect(screen.getByText('预计剩余')).toBeTruthy();
    expect(screen.getByText(/约 .*（估算）/)).toBeTruthy();
    useScanStore.getState().reset();
  });

  it('事件不足 2 个时预计剩余显示「估算中…」', () => {
    useScanStore.getState().reset();
    useScanStore.setState({
      status: 'running',
      events: [
        { type: 'point_discovered', scanId: 's', ts: new Date(0).toISOString(), payload: null } as ScanEvent,
      ],
    });
    render(<ProgressView />);
    expect(screen.getByText('估算中…')).toBeTruthy();
    useScanStore.getState().reset();
  });
});

describe('ProgressView 实时指标面板', () => {
  it('渲染注入点 / 二阶确认 / 并发度等指标', () => {
    useScanStore.getState().reset();
    useScanStore.setState({
      status: 'running',
      discoveredPoints: [
        { id: 'p1', location: 'url', param: 'id', originalValue: '1', confirmed: true, technique: 'union', dbms: 'MySQL' },
        { id: 'p2', location: 'url', param: 'x', originalValue: '1', confirmed: false, technique: 'boolean', dbms: 'MySQL' },
        { id: 'p3', location: 'url', param: 'y', originalValue: '1', confirmed: false, technique: 'error', dbms: 'MySQL' },
      ] as any,
      confirmedVulnPointIds: ['p1'],
      secondOrderDiscovery: { candidates: ['u1', 'u2', 'u3'], confirmed: ['u1'] },
      scanConcurrency: 7,
      events: [{ type: 'detection_found', ts: '1', payload: null } as ScanEvent],
    });
    render(<ProgressView />);
    expect(screen.getByText('注入点')).toBeTruthy();
    expect(screen.getByText('3')).toBeTruthy();
    expect(screen.getByText('二阶确认')).toBeTruthy();
    expect(screen.getByText('1/3')).toBeTruthy();
    expect(screen.getByText('并发度')).toBeTruthy();
    expect(screen.getByText('7')).toBeTruthy();
    // 因 detection_found 事件 → 阶段「确认漏洞」80%
    expect(screen.getByText('确认漏洞')).toBeTruthy();
    expect(screen.getByText('80%')).toBeTruthy();
  });
});

describe('ProgressView SSE 实时连接状态指示', () => {
  it('sseStatus=open → 显示「实时已连接」', () => {
    useScanStore.getState().reset();
    useScanStore.setState({ sseStatus: 'open' });
    render(<ProgressView />);
    expect(screen.getByText('实时已连接')).toBeTruthy();
    useScanStore.getState().reset();
  });
  it('sseStatus=connecting → 显示「连接中…」', () => {
    useScanStore.getState().reset();
    useScanStore.setState({ sseStatus: 'connecting' });
    render(<ProgressView />);
    expect(screen.getByText('连接中…')).toBeTruthy();
    useScanStore.getState().reset();
  });
  it('sseStatus=reconnecting → 显示「重连中…」', () => {
    useScanStore.getState().reset();
    useScanStore.setState({ sseStatus: 'reconnecting' });
    render(<ProgressView />);
    expect(screen.getByText('重连中…')).toBeTruthy();
    useScanStore.getState().reset();
  });
  it('sseStatus=idle（默认）→ 显示「未连接」', () => {
    useScanStore.getState().reset();
    render(<ProgressView />);
    expect(screen.getByText('未连接')).toBeTruthy();
    useScanStore.getState().reset();
  });
});
