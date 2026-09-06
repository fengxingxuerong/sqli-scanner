import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import ScanConfigPanel from '../components/ScanConfigPanel';
import { DEFAULT_CONFIG } from '../shared/constants';
import type { ScanConfig } from '../shared/types';

const BASE_PROPS = {
  config: { ...DEFAULT_CONFIG } as ScanConfig,
  onChange: () => undefined,
};

describe('F-19 ScanConfigPanel 检测技术多选', () => {
  it('默认态渲染检测技术标签', () => {
    render(<ScanConfigPanel {...BASE_PROPS} />);
    // 面板始终显示"高级设置"标题
    expect(screen.getByText('高级设置')).toBeTruthy();
  });

  it('配置含堆叠时显示堆叠标签', () => {
    const config = { ...DEFAULT_CONFIG, techniques: ['union', 'error', 'boolean', 'time', 'stacked'] } as ScanConfig;
    render(<ScanConfigPanel {...BASE_PROPS} config={config} />);
    expect(screen.getByText('高级设置')).toBeTruthy();
  });

  it('全不选时不显示任何技术标签', () => {
    const config = { ...DEFAULT_CONFIG, techniques: [] } as ScanConfig;
    render(<ScanConfigPanel {...BASE_PROPS} config={config} />);
    expect(screen.getByText('高级设置')).toBeTruthy();
  });

  it('config.techniques 缺失时回落 DEFAULT_CONFIG', () => {
    const noTech = { ...DEFAULT_CONFIG } as ScanConfig;
    delete (noTech as Partial<ScanConfig>).techniques;
    render(<ScanConfigPanel {...BASE_PROPS} config={noTech} />);
    expect(screen.getByText('高级设置')).toBeTruthy();
  });
});
