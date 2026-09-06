import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { useState } from 'react';
import type { TamperConfig, WafSuggestion } from '../shared/types';
import WafTamperPanel from '../components/WafTamperPanel';

// 拦截 tamper 清单请求（组件挂载即 fetch /api/tampers），返回受控小清单
vi.mock('../shared/apiClient', () => ({
  apiClient: {
    tampers: vi.fn().mockResolvedValue([
      { name: 'space2comment', description: '空格转内联注释' },
      { name: 'randomcase', description: '随机大小写' },
      { name: 'charencode', description: 'URL 编码' },
      { name: 'modsecurityversioned', description: 'ModSecurity 版本注释包裹' },
    ]),
  },
}));

const DEFAULT: TamperConfig = { enabled: false, plugins: [], intensity: 'medium' };

// 受控容器：持有 value 状态，onChange 透传 setValue
function Harness({ initial = DEFAULT, suggestion }: { initial?: TamperConfig; suggestion?: WafSuggestion[] }) {
  const [value, setValue] = useState<TamperConfig>(initial);
  return <WafTamperPanel value={value} onChange={setValue} suggestion={suggestion} />;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('WafTamperPanel', () => {
  it('默认态：enabled=false / plugins=[] / intensity=medium', async () => {
    render(<Harness />);
    const sw = screen.getByLabelText(/启用 tamper 变换/) as HTMLInputElement;
    expect(sw.checked).toBe(false);
    const medium = screen.getByLabelText('中度') as HTMLInputElement;
    expect(medium.checked).toBe(true);
    // 等待清单加载后出现「未选择任何 tamper」
    await screen.findByText('未选择任何 tamper');
  });

  it('勾选插件 → 加入有序组合（顺序=勾选顺序）', async () => {
    render(<Harness />);
    const cb1 = await screen.findByRole('checkbox', { name: /space2comment/ });
    const cb2 = await screen.findByRole('checkbox', { name: /randomcase/ });
    fireEvent.click(cb1);
    fireEvent.click(cb2);
    await screen.findByText('1. space2comment');
    await screen.findByText('2. randomcase');
  });

  it('上移/下移改变链式顺序', async () => {
    render(<Harness initial={{ enabled: false, plugins: ['space2comment', 'randomcase'], intensity: 'medium' }} />);
    // 初始 1. space2comment / 2. randomcase
    await screen.findByText('1. space2comment');
    // 点击第一组「下移」→ 顺序变为 randomcase, space2comment
    const downs = screen.getAllByLabelText('下移');
    fireEvent.click(downs[0]);
    await screen.findByText('1. randomcase');
    await screen.findByText('2. space2comment');
  });

  it('强度预设一键填充 plugins（激进=6 项）', async () => {
    render(<Harness />);
    const high = screen.getByLabelText('激进') as HTMLInputElement;
    fireEvent.click(high);
    await screen.findByText('1. space2comment');
    await screen.findByText('6. versionedkeywords');
  });

  it('WAF 推荐「一键应用」只写 plugins，不改 enabled', async () => {
    const suggestion: WafSuggestion[] = [
      { vendor: 'Cloudflare', plugins: ['space2comment', 'randomcase', 'charencode'] },
    ];
    render(<Harness suggestion={suggestion} />);
    // 建议区渲染
    await screen.findByText(/Cloudflare/);
    const applyBtn = screen.getByLabelText('应用 Cloudflare 推荐');
    fireEvent.click(applyBtn);
    await screen.findByText('1. space2comment');
    await screen.findByText('3. charencode');
    const sw = screen.getByLabelText(/启用 tamper 变换/) as HTMLInputElement;
    expect(sw.checked).toBe(false); // enabled 未被一键应用改变
  });
});
