// ScanWizard 组件测试：渲染 / 开始回调 / 停止按钮 / 引擎切换 / 高级展开收起
import { describe, it, expect, vi } from 'vitest';
import type { ComponentProps } from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import ScanWizard from '../components/ScanWizard';
import { DEFAULT_CONFIG, DEFAULT_SQLMAP_CONFIG } from '../shared/constants';
import type { ScanConfig, SqlmapConfig } from '../shared/types';

// ── mock 子组件，隔离 ScanWizard 自身逻辑 ──
vi.mock('../components/TargetForm', () => ({
  default: () => <div data-testid="target-form" />,
}));
vi.mock('../components/ScanConfigPanel', () => ({
  default: () => <div data-testid="scan-config-panel" />,
}));
vi.mock('../components/SqlmapOptions', () => ({
  default: () => <div data-testid="sqlmap-options" />,
}));

// ── mock react-router-dom：useNavigate 返回桩函数，避免 Router 依赖 ──
vi.mock('react-router-dom', () => ({
  useNavigate: () => vi.fn(),
}));

// ── mock apiClient：sqlmap 预检桩为可用，避免真实 HTTP ──
vi.mock('../shared/apiClient', () => ({
  sqlmapClient: { status: vi.fn().mockResolvedValue({ available: true, maxConcurrent: 2 }) },
}));

// ── 默认 props 工厂 ──
// 手抄的 config 字面量会随 ScanConfig 演进而变成"不存在的形态"（本文件的 techniques 曾被推成
// string[]、且缺了一批必填键，全靠 makeProps 那层宽松类型没报）。改成从真实默认值派生 + 显式标注。
const BASE_CONFIG: ScanConfig = {
  ...DEFAULT_CONFIG,
  concurrency: 4,
  timeoutMs: 5000,
  retry: 2,
  timeThresholdMs: 3000,
  ratePerSec: 5,
  enableExtract: false,
  techniques: ['boolean'],
};
const BASE_SQLMAP: SqlmapConfig = { ...DEFAULT_SQLMAP_CONFIG };

// 返回类型显式钉成组件 props（ScanWizardProps 未导出 ⇒ 用 ComponentProps 取，不动生产代码）：
// 新增必填 prop 时（本批就是 onPause/onResume），错在这一个工厂函数里报一次，
// 而不是 5 个 render 各报一次；且不再有"缺 prop 也能渲染"的漏网。
function makeProps(over: Partial<ComponentProps<typeof ScanWizard>> = {}): ComponentProps<typeof ScanWizard> {
  return {
    url: '', method: 'GET', bodyText: '', cookieText: '', headerText: '',
    config: BASE_CONFIG, sqlmapConfig: BASE_SQLMAP,
    engine: 'builtin', running: false, starting: false, error: '',
    wafSuggestion: null, status: 'pending',
    onUrlChange: vi.fn(), onMethodChange: vi.fn(), onBodyTextChange: vi.fn(),
    onCookieTextChange: vi.fn(), onHeaderTextChange: vi.fn(),
    onConfigChange: vi.fn(), onSqlmapConfigChange: vi.fn(),
    onEngineChange: vi.fn(), onErrorClear: vi.fn(), onStart: vi.fn(), onStop: vi.fn(),
    onPause: vi.fn(), onResume: vi.fn(),
    ...over,
  };
}

// 取「高级设置」按钮里的展开/收起图标 path（ExpandMore vs ExpandLess）
function advIconPath(): string | null {
  const btn = screen.getByRole('button', { name: '高级设置' }) as HTMLElement;
  return btn.querySelector('svg path')?.getAttribute('d') ?? null;
}

describe('ScanWizard 组件', () => {
  it('渲染标题 / URL 输入框 / 开始扫描按钮', () => {
    render(<ScanWizard {...makeProps()} />);
    expect(screen.getByText('SQL 注入检测')).toBeTruthy();
    // MUI OutlinedInput 的 label 文案会出现在 <label> 与 <legend> 两处
    expect(screen.getAllByText('目标 URL').length).toBeGreaterThan(0);
    expect(screen.getByPlaceholderText('http://example.com/item.php?id=1')).toBeTruthy();
    expect(screen.getByRole('button', { name: '开始扫描' })).toBeTruthy();
  });

  it('点击「开始扫描」触发 onStart', () => {
    const onStart = vi.fn();
    render(<ScanWizard {...makeProps({ onStart })} />);
    fireEvent.click(screen.getByRole('button', { name: '开始扫描' }));
    expect(onStart).toHaveBeenCalledTimes(1);
  });

  it('running 状态显示「停止扫描」按钮且点击触发 onStop', () => {
    const onStop = vi.fn();
    render(<ScanWizard {...makeProps({ running: true, onStop })} />);
    const stopBtn = screen.getByRole('button', { name: '停止扫描' });
    expect(stopBtn).toBeTruthy();
    fireEvent.click(stopBtn);
    expect(onStop).toHaveBeenCalledTimes(1);
  });

  it('引擎切换：点击 sqlmap / builtin Chip 触发 onEngineChange', () => {
    const onEngineChange = vi.fn();
    render(<ScanWizard {...makeProps({ onEngineChange })} />);
    // 展开高级设置，使引擎 Chip 出现且可交互
    fireEvent.click(screen.getByRole('button', { name: '高级设置' }));
    fireEvent.click(screen.getByText('sqlmap 高级模式'));
    expect(onEngineChange).toHaveBeenCalledWith('sqlmap');
    fireEvent.click(screen.getByText('自带引擎（教学/合规）'));
    expect(onEngineChange).toHaveBeenCalledWith('builtin');
  });

  it('高级设置展开/收起：点击切换 ExpandMore ↔ ExpandLess 图标', () => {
    render(<ScanWizard {...makeProps()} />);
    // 初始收起 → ExpandMore
    expect(advIconPath()).toContain('8.59');
    fireEvent.click(screen.getByRole('button', { name: '高级设置' }));
    // 展开后 → ExpandLess
    expect(advIconPath()).toContain('m12 8-6 6');
    fireEvent.click(screen.getByRole('button', { name: '高级设置' }));
    // 再次收起 → 回到 ExpandMore
    expect(advIconPath()).toContain('8.59');
  });
});
