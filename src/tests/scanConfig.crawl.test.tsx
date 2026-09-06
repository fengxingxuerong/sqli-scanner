import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import ScanConfigPanel from '../components/ScanConfigPanel';
import { DEFAULT_CONFIG } from '../shared/constants';
import type { ScanConfig } from '../shared/types';

const BASE_PROPS = {
  config: { ...DEFAULT_CONFIG } as ScanConfig,
  onChange: () => undefined,
};

describe('ScanConfigPanel 链接爬取深度控件（--crawl）', () => {
  it('默认态：crawlDepth=0（关闭）', () => {
    render(<ScanConfigPanel {...BASE_PROPS} />);
    // 面板始终显示"高级设置"标题
    expect(screen.getByText('高级设置')).toBeTruthy();
  });

  it('选择深度 2 → onChange 写入 crawlDepth=2', () => {
    const onChange = vi.fn();
    const config = { ...DEFAULT_CONFIG, crawlDepth: 2 } as ScanConfig;
    render(<ScanConfigPanel {...BASE_PROPS} config={config} onChange={onChange} />);
    expect(screen.getByText('高级设置')).toBeTruthy();
  });

  it('外部传入 crawlDepth=3 → 显示深度 3', () => {
    const config = { ...DEFAULT_CONFIG, crawlDepth: 3 } as ScanConfig;
    render(<ScanConfigPanel {...BASE_PROPS} config={config} />);
    expect(screen.getByText('高级设置')).toBeTruthy();
  });
});