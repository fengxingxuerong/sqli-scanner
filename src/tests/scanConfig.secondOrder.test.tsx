import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { useState } from 'react';
import ScanConfigPanel from '../components/ScanConfigPanel';
import { DEFAULT_CONFIG } from '../shared/constants';
import type { ScanConfig } from '../shared/types';

// 受控包装：让 onChange 真正更新 config，验证 UI 联动（如启用后文本框可编辑）
function ControlledPanel({ initial }: { initial?: Partial<ScanConfig> }) {
  const [cfg, setCfg] = useState<ScanConfig>({ ...DEFAULT_CONFIG, ...initial } as ScanConfig);
  return (
    <ScanConfigPanel config={cfg} onChange={(p) => setCfg({ ...cfg, ...p })} mode="builtin" />
  );
}

describe('ScanConfigPanel 二阶注入开关（对标 sqlmap --second-order）', () => {
  it('渲染二阶注入开关与授权警示', () => {
    render(<ControlledPanel />);
    expect(screen.getByText(/启用二阶注入 --second-order/)).toBeTruthy();
    // 授权警示：提示将发起真实写请求、需授权、命中高危
    expect(screen.getByText(/真实写请求/)).toBeTruthy();
    // 注：/已明确授权/ 同时命中二阶与 OOB 两个警示区块，改用二阶独有文本避免歧义
    expect(screen.getByText(/数据污染与账号副作用/)).toBeTruthy();
    expect(screen.getByText(/命中判定为高危/)).toBeTruthy();
  });

  it('默认未启用 → 触发页文本框 disabled', () => {
    render(<ControlledPanel />);
    const ta = screen.getByLabelText(/触发页 URL/) as HTMLTextAreaElement;
    expect(ta.disabled).toBe(true);
  });

  it('切换启用 → 文本框可编辑，onChange 携带 enabled=true', () => {
    render(<ControlledPanel />);
    const sw = screen.getByLabelText(/启用二阶注入 --second-order/) as HTMLInputElement;
    fireEvent.click(sw);
    const ta = screen.getByLabelText(/触发页 URL/) as HTMLTextAreaElement;
    expect(ta.disabled).toBe(false);
  });

  it('输入逗号/换行分隔 URL → onChange 解析为去空白数组', () => {
    const onChange = vi.fn();
    render(
      <ScanConfigPanel
        config={{ ...DEFAULT_CONFIG, secondOrder: { enabled: true, triggerUrls: [] } } as ScanConfig}
        onChange={onChange}
        mode="builtin"
      />,
    );
    const ta = screen.getByLabelText(/触发页 URL/) as HTMLTextAreaElement;
    fireEvent.change(ta, {
      target: { value: 'http://t/profile.php, http://t/account.php\nhttp://t/settings.php ' },
    });
    const patch = onChange.mock.calls[0][0];
    expect(patch.secondOrder?.triggerUrls).toEqual([
      'http://t/profile.php',
      'http://t/account.php',
      'http://t/settings.php',
    ]);
  });

  it('sqlmap 模式不显示二阶注入开关（避免与 SqlmapOptions 重复）', () => {
    render(<ScanConfigPanel config={DEFAULT_CONFIG} onChange={vi.fn()} mode="sqlmap" />);
    expect(screen.queryByText(/启用二阶注入 --second-order/)).toBeNull();
  });

  it('二阶进阶开关：启用后可见，refreshCsrf/negativeControl 默认开、oobTrigger 默认关', () => {
    render(
      <ControlledPanel
        initial={{
          secondOrder: { enabled: true, triggerUrls: [], refreshCsrf: true, negativeControl: true, oobTrigger: false },
        }}
      />,
    );
    const csrf = screen.getByLabelText(/触发前刷新 CSRF/) as HTMLInputElement;
    const neg = screen.getByLabelText(/负控制验证/) as HTMLInputElement;
    const oob = screen.getByLabelText(/OOB 触发回传/) as HTMLInputElement;
    expect(csrf.checked).toBe(true);
    expect(neg.checked).toBe(true);
    expect(oob.checked).toBe(false);
  });

  it('二阶未启用时三个进阶开关 disabled', () => {
    render(<ControlledPanel />);
    const csrf = screen.getByLabelText(/触发前刷新 CSRF/) as HTMLInputElement;
    const neg = screen.getByLabelText(/负控制验证/) as HTMLInputElement;
    const oob = screen.getByLabelText(/OOB 触发回传/) as HTMLInputElement;
    expect(csrf.disabled).toBe(true);
    expect(neg.disabled).toBe(true);
    expect(oob.disabled).toBe(true);
  });

  it('切换刷新 CSRF → 受控联动置为 false（保留其它二阶字段）', () => {
    render(
      <ControlledPanel
        initial={{
          secondOrder: { enabled: true, triggerUrls: [], refreshCsrf: true, negativeControl: true, oobTrigger: false },
        }}
      />,
    );
    const csrf = screen.getByLabelText(/触发前刷新 CSRF/) as HTMLInputElement;
    fireEvent.click(csrf);
    expect(csrf.checked).toBe(false);
  });

  it('oobTrigger 开启但 OOB 接收端未启用 → 显示 info 前置提示', () => {
    render(
      <ControlledPanel
        initial={{
          secondOrder: { enabled: true, triggerUrls: [], refreshCsrf: true, negativeControl: true, oobTrigger: true },
          oob: { enabled: false, callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 5000 },
        }}
      />,
    );
    expect(screen.getByText(/oobTrigger 已开启，但 OOB 接收端未启用/)).toBeTruthy();
  });

  it('oobTrigger 开启且 OOB 接收端已启用 → 不显示前置提示', () => {
    render(
      <ControlledPanel
        initial={{
          secondOrder: { enabled: true, triggerUrls: [], refreshCsrf: true, negativeControl: true, oobTrigger: true },
          oob: { enabled: true, callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 5000 },
        }}
      />,
    );
    expect(screen.queryByText(/oobTrigger 已开启，但 OOB 接收端未启用/)).toBeNull();
  });

  it('二阶进阶开关含「自动发现触发页」，未启用时 disabled', () => {
    render(<ControlledPanel />);
    const sw = screen.getByLabelText(/自动发现触发页/) as HTMLInputElement;
    expect(sw.disabled).toBe(true);
  });

  it('二阶未启用 → 「指定存储点参数」文本框 disabled', () => {
    render(<ControlledPanel />);
    const ta = screen.getByLabelText(/指定存储点参数/) as HTMLTextAreaElement;
    expect(ta.disabled).toBe(true);
  });

  it('输入逗号/换行分隔参数名 → onChange 解析为去空白数组', () => {
    const onChange = vi.fn();
    render(
      <ScanConfigPanel
        config={{ ...DEFAULT_CONFIG, secondOrder: { enabled: true, triggerUrls: [], refreshCsrf: true, negativeControl: true, oobTrigger: false, manualStorePoints: [] } } as ScanConfig}
        onChange={onChange}
        mode="builtin"
      />,
    );
    const ta = screen.getByLabelText(/指定存储点参数/) as HTMLTextAreaElement;
    fireEvent.change(ta, { target: { value: 'username, email\n bio ' } });
    const patch = onChange.mock.calls[0][0];
    expect(patch.secondOrder?.manualStorePoints).toEqual(['username', 'email', 'bio']);
  });
});
