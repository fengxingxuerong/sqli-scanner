import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import ScanConfigPanel from '../components/ScanConfigPanel';
import { DEFAULT_CONFIG } from '../shared/constants';
import type { ScanConfig, EngineType } from '../shared/types';

// `mode` 是 ScanConfigPanelProps 的**必填** prop（引擎切换决定一批控件的显隐）；
// 缺它时组件在 jsdom 里照样渲染，于是这个文件曾经测的是"mode=undefined 的分支"。
const BASE_PROPS = {
  config: { ...DEFAULT_CONFIG } as ScanConfig,
  mode: 'builtin' as EngineType,
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