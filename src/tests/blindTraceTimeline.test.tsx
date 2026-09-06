import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import BlindTraceTimeline from '../components/BlindTraceTimeline';
import type { BlindTrace } from '../shared/types';

describe('BlindTraceTimeline', () => {
  const boolTrace: BlindTrace = {
    technique: 'boolean',
    adaptive: false,
    baselineNoiseRate: 0.05,
    minStable: 0.8,
    baselineSamples: [
      { idx: 0, len: 1200, likeBaseline: true },
      { idx: 1, len: 1210, likeBaseline: true },
    ],
    pairs: [
      {
        ti: 0,
        fi: 1,
        trueSamples: [{ idx: 0, len: 1200, likeBaseline: true }],
        falseSamples: [{ idx: 1, len: 1500, likeBaseline: false }],
        trueRatio: 0.95,
        falseRatio: 0.3,
        meaningfulRatio: 0.65,
        z: 3.2,
        significant: true,
      },
    ],
    decision: 'vulnerable',
  };

  const timeTrace: BlindTrace = {
    technique: 'time',
    adaptive: true,
    mu: 0.5,
    sigma: 0.1,
    threshold: 2.0,
    floor: 1.0,
    stableRatio: 0.9,
    baselineSamples: [],
    injectSamples: [
      { idx: 0, ms: 0.5, delayed: false },
      { idx: 1, ms: 2.5, delayed: true },
    ],
    decision: 'vulnerable',
  };

  const emptyTrace: BlindTrace = {
    technique: 'boolean',
    adaptive: false,
    baselineSamples: [],
    pairs: [],
    decision: 'clean',
  };

  it('渲染「判定时间线」标题', () => {
    render(<BlindTraceTimeline trace={boolTrace} />);
    expect(screen.getByText('判定时间线')).toBeInTheDocument();
  });

  it('空事件渲染占位文案', () => {
    render(<BlindTraceTimeline trace={emptyTrace} />);
    // baselineSamples 为空时显示「基线采样（0 次）」
    expect(screen.getByText('基线采样（0 次）')).toBeInTheDocument();
  });

  it('传入事件渲染正确的标签文本', () => {
    render(<BlindTraceTimeline trace={boolTrace} />);
    // 基线采样 chip
    expect(screen.getByText('#0 1200B')).toBeInTheDocument();
    expect(screen.getByText('#1 1210B')).toBeInTheDocument();
    // 真假对摘要文本（其中包含 index 信息）
    expect(screen.getByText(/真假对 #1/)).toBeInTheDocument();
    // 决策标签
    expect(screen.getByText('命中')).toBeInTheDocument();
  });

  it('指标标签渲染（基线噪声率、自适应阈值）', () => {
    // 布尔轨迹：基线噪声率
    render(<BlindTraceTimeline trace={boolTrace} />);
    expect(screen.getByText('基线噪声率')).toBeInTheDocument();
    expect(screen.getByText('0.05')).toBeInTheDocument();

    // 时间轨迹：自适应阈值 + 自适应门槛标签
    render(<BlindTraceTimeline trace={timeTrace} />);
    expect(screen.getByText('阈值')).toBeInTheDocument();
    expect(screen.getByText('2.00s')).toBeInTheDocument();
    expect(screen.getByText('自适应门槛')).toBeInTheDocument();
  });
});