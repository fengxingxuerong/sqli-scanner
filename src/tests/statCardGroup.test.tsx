import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import StatCardGroup from '../components/progress/StatCardGroup';

const BASE = {
  total: 12,
  pointsTested: 8,
  vulnFound: 0,
  wafDetected: 0,
  elapsed: '00:42',
  running: false,
};

describe('StatCardGroup 统计卡片', () => {
  it('渲染 检测点/已测试/漏洞/耗时 四张基础卡片', () => {
    render(<StatCardGroup {...BASE} />);
    expect(screen.getByText('检测点')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
    expect(screen.getByText('已测试')).toBeInTheDocument();
    expect(screen.getByText('8')).toBeInTheDocument();
    expect(screen.getByText('漏洞')).toBeInTheDocument();
    expect(screen.getByText('耗时')).toBeInTheDocument();
    expect(screen.getByText('00:42')).toBeInTheDocument();
  });

  it('数值为 0 显示占位符 -', () => {
    render(<StatCardGroup {...BASE} total={0} pointsTested={0} />);
    const dashes = screen.getAllByText('-');
    expect(dashes.length).toBeGreaterThanOrEqual(2);
  });

  it('vulnFound>0 显示「N !」并标红；=0 且未运行显示「✓ 安全」', () => {
    const { rerender } = render(<StatCardGroup {...BASE} vulnFound={3} />);
    expect(screen.getByText('3 !')).toBeInTheDocument();

    rerender(<StatCardGroup {...BASE} vulnFound={0} running={false} />);
    expect(screen.getByText('✓ 安全')).toBeInTheDocument();

    // 运行中且 0 漏洞：显示占位符而非「安全」
    rerender(<StatCardGroup {...BASE} vulnFound={0} running={true} />);
    expect(screen.queryByText('✓ 安全')).not.toBeInTheDocument();
  });

  it('wafDetected>0 时显示 WAF 卡片，否则隐藏', () => {
    const { rerender } = render(<StatCardGroup {...BASE} wafDetected={1} />);
    expect(screen.getByText('WAF')).toBeInTheDocument();
    expect(screen.getByText('已识别')).toBeInTheDocument();

    rerender(<StatCardGroup {...BASE} wafDetected={0} />);
    expect(screen.queryByText('已识别')).not.toBeInTheDocument();
  });

  it('elapsed 为空字符串时隐藏耗时卡片', () => {
    render(<StatCardGroup {...BASE} elapsed="" />);
    expect(screen.queryByText('耗时')).not.toBeInTheDocument();
  });
});
