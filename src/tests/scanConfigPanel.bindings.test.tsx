// ============================================================================
// src/tests/scanConfigPanel.bindings.test.tsx —— 配置面板「控件 → 键」的接线
// ============================================================================
// 为什么补这一份：ScanConfigPanel 是最大的前端模块（870 行），
// **函数覆盖只有 31.6%** —— 意味着绝大多数交互回调从未被执行过。
// 它的失败形态不是报错，而是「用户点了 A，请求体里改的是 B」或
// 「关掉的开关发了个空值让后端去猜」，两种都不会让任何既有用例变红。
//
// 手法：受控 harness 回放真实点击/输入，断言 onChange 收到的 **patch 键名与值形态**。
// 文案从 zh.json 取（改文案不会让测试空转）。
// ============================================================================
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useState } from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import ScanConfigPanel from '../components/ScanConfigPanel';
import { DEFAULT_CONFIG } from '../shared/constants';
import type { ScanConfig, EngineType } from '../shared/types';
import zh from '../i18n/zh.json';

vi.mock('../shared/apiClient', () => ({
  apiClient: { tampers: vi.fn().mockResolvedValue([]), get: vi.fn(), post: vi.fn() },
}));

const L = (k: string) => (zh.scanConfig as Record<string, string>)[k];

function PanelHarness({
  initial,
  mode = 'builtin',
  onChangeSpy,
}: {
  initial: ScanConfig;
  mode?: EngineType;
  onChangeSpy: (patch: Partial<ScanConfig>) => void;
}) {
  const [config, setConfig] = useState<ScanConfig>(initial);
  return (
    <ScanConfigPanel
      config={config}
      mode={mode}
      onChange={(patch) => {
        onChangeSpy(patch);
        setConfig((c) => ({ ...c, ...patch }));
      }}
    />
  );
}

const makeConfig = (over: Partial<ScanConfig> = {}): ScanConfig => ({ ...DEFAULT_CONFIG, ...over }) as ScanConfig;

describe('ScanConfigPanel：控件 → 配置键的接线', () => {
  let onChange: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    onChange = vi.fn();
  });

  const renderPanel = (over: Partial<ScanConfig> = {}) => {
    render(<PanelHarness initial={makeConfig(over)} onChangeSpy={onChange} />);
  };

  it('① crawlForms 开关 → patch 的键必须是 crawlForms（六键 UI 入口之一）', () => {
    renderPanel({ crawlForms: false });
    const sw = screen.getByLabelText(L('crawlFormsLabel')) as HTMLInputElement;
    expect(sw.checked).toBe(false);
    fireEvent.click(sw);
    expect(onChange).toHaveBeenCalledWith({ crawlForms: true });
  });

  it('② matchTitle 开关 → 键必须是 matchTitle（写错键 = 用户勾了但引擎收不到）', () => {
    renderPanel({ matchTitle: false });
    fireEvent.click(screen.getByLabelText(L('matchTitleLabel')));
    expect(onChange).toHaveBeenCalledWith({ matchTitle: true });
  });

  it('③ productionMode 默认开，点击后必须真的传出 false（安全默认不能被静默吞掉）', () => {
    renderPanel({ productionMode: true });
    const sw = screen.getByLabelText(L('productionModeLabel')) as HTMLInputElement;
    expect(sw.checked).toBe(true);
    fireEvent.click(sw);
    expect(onChange).toHaveBeenCalledWith({ productionMode: false });
  });

  it('④ 文本型键：空串必须传 undefined（关闭态在请求体里干脆没这个键）', () => {
    renderPanel({ matchRegexp: undefined });
    const input = screen.getByLabelText(L('matchRegexpLabel')) as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'Welcome' } });
    expect(onChange).toHaveBeenCalledWith({ matchRegexp: 'Welcome' });
    onChange.mockClear();
    fireEvent.change(input, { target: { value: '  ' } });
    expect(onChange).toHaveBeenCalledWith({ matchRegexp: undefined });
  });

  it('⑤ matchCode 是对象形态：填 true 侧 → { matchCode: { true: 200 } }', () => {
    renderPanel({ matchCode: undefined });
    const input = screen.getByLabelText(L('matchCodeTruePlaceholder')) as HTMLInputElement;
    fireEvent.change(input, { target: { value: '200' } });
    expect(onChange).toHaveBeenCalledWith({ matchCode: { true: 200 } });
  });

  it('⑤ 两侧都清空 → 整个键传 undefined（不启用就别在请求体里留空对象）', () => {
    renderPanel({ matchCode: { true: 200 } });
    const input = screen.getByLabelText(L('matchCodeTruePlaceholder')) as HTMLInputElement;
    fireEvent.change(input, { target: { value: '' } });
    expect(onChange).toHaveBeenCalledWith({ matchCode: undefined });
  });

  it('⑥ matchCode 小数输入取整（状态码必须是整数，200.7 不能原样进请求体）', () => {
    renderPanel({ matchCode: undefined });
    const input = screen.getByLabelText(L('matchCodeTruePlaceholder')) as HTMLInputElement;
    fireEvent.change(input, { target: { value: '200.7' } });
    expect(onChange).toHaveBeenCalledWith({ matchCode: { true: 200 } });
  });

  it('⑥ 越界值原样传出（UI 不擅自吞掉用户输入，clamp 交给后端单一事实来源）', () => {
    renderPanel({ matchCode: undefined });
    const input = screen.getByLabelText(L('matchCodeTruePlaceholder')) as HTMLInputElement;
    expect(input.type).toBe('number');
    fireEvent.change(input, { target: { value: '700' } });
    expect(onChange).toHaveBeenCalledWith({ matchCode: { true: 700 } });
  });

  it('⑦ scope 逗号串 → 数组；留空 → undefined（留空 = 不启用范围限制）', () => {
    renderPanel({ scope: undefined });
    const input = screen.getByPlaceholderText(L('scopePlaceholder')) as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'a.example.com, b.example.com' } });
    expect(onChange).toHaveBeenCalledWith({ scope: ['a.example.com', 'b.example.com'] });
    onChange.mockClear();
    fireEvent.change(input, { target: { value: '   ' } });
    expect(onChange).toHaveBeenCalledWith({ scope: undefined });
  });

  it('⑧ 开关类控件不得把值写成字符串（"false" 在后端是真值 —— 关了等于没关）', () => {
    renderPanel({ productionMode: true });
    fireEvent.click(screen.getByLabelText(L('productionModeLabel')));
    const patch = onChange.mock.calls[0][0] as Record<string, unknown>;
    expect(patch.productionMode).toBe(false);
    expect(typeof patch.productionMode).toBe('boolean');
  });
});
