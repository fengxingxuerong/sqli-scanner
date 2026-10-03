import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import SqlmapOptions from '../components/SqlmapOptions';
import { DEFAULT_SQLMAP_CONFIG } from '../shared/constants';

// Mock apiClient：组件 useEffect 会调用 apiClient.tampers()，需避免真实网络请求
vi.mock('../shared/apiClient', () => ({
  apiClient: {
    tampers: vi.fn().mockResolvedValue([]),
    get: vi.fn(),
    post: vi.fn(),
  },
}));

describe('SqlmapOptions', () => {
  let mockOnChange: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockOnChange = vi.fn();
    vi.clearAllMocks();
  });

  it('渲染「检测强度」标题和「风险等级」Slider', () => {
    render(<SqlmapOptions config={DEFAULT_SQLMAP_CONFIG} onChange={mockOnChange} />);
    expect(screen.getByText('检测强度')).toBeInTheDocument();
    // riskLabel 包含「风险等级」字样
    expect(screen.getByText(/风险等级/)).toBeInTheDocument();
  });

  it('渲染 sqlmap 高级参数区块（至少一个 TextField）', () => {
    render(<SqlmapOptions config={DEFAULT_SQLMAP_CONFIG} onChange={mockOnChange} />);
    expect(screen.getByText('sqlmap 高级参数')).toBeInTheDocument();
    // 高级参数区块含 --time-sec / --ignore-code 等 label（MUI 同时渲染 label 和 span，用 getAllByText）
    expect(screen.getAllByText('--time-sec').length).toBeGreaterThan(0);
    expect(screen.getAllByText('--ignore-code').length).toBeGreaterThan(0);
  });

  it('渲染排除系统库开关', () => {
    render(<SqlmapOptions config={DEFAULT_SQLMAP_CONFIG} onChange={mockOnChange} />);
    expect(screen.getByText('--exclude-sysdbs')).toBeInTheDocument();
  });

  it('渲染检测技术 Checkbox（B/E/U/S/T/Q）', () => {
    render(<SqlmapOptions config={DEFAULT_SQLMAP_CONFIG} onChange={mockOnChange} />);
    for (const letter of ['B', 'E', 'U', 'S', 'T', 'Q']) {
      expect(screen.getByText(new RegExp(`^${letter} ·`))).toBeInTheDocument();
    }
  });

  it('修改 level Slider 触发 onChange', () => {
    render(<SqlmapOptions config={DEFAULT_SQLMAP_CONFIG} onChange={mockOnChange} />);
    // 第一个 slider 是 level（type=range, min=1, max=5）
    const sliders = screen.getAllByRole('slider') as HTMLInputElement[];
    const levelSlider = sliders[0];
    expect(levelSlider).toHaveAttribute('aria-valuenow', '1');
    // MUI Slider 的 onChange 联到 native input change 事件
    fireEvent.change(levelSlider, { target: { value: '3' } });
    expect(mockOnChange).toHaveBeenCalledWith({ level: 3 });
  });

  it('切换技术 Checkbox 触发 onChange', () => {
    // 以空 techniques 起，勾选 B 应产出 { techniques: ['B'] }
    const config = { ...DEFAULT_SQLMAP_CONFIG, techniques: [] as string[] };
    render(<SqlmapOptions config={config} onChange={mockOnChange} />);
    const techLabel = screen.getByText(/^B ·/).closest('label');
    const checkbox = techLabel!.querySelector('input[type="checkbox"]') as HTMLInputElement;
    expect(checkbox).not.toBeNull();
    fireEvent.click(checkbox);
    expect(mockOnChange).toHaveBeenCalledWith({ techniques: ['B'] });
  });
});

describe('SqlmapOptions 交互分支补充', () => {
  let mockOnChange: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockOnChange = vi.fn();
    vi.clearAllMocks();
  });

  function checkOf(labelText: string): HTMLInputElement {
    const label = screen.getByText(labelText).closest('label');
    return label!.querySelector('input[type="checkbox"]') as HTMLInputElement;
  }

  it('取消勾选技术 Checkbox → 从 techniques 中过滤掉该项', () => {
    const config = { ...DEFAULT_SQLMAP_CONFIG, techniques: ['B', 'E'] };
    render(<SqlmapOptions config={config} onChange={mockOnChange} />);
    fireEvent.click(checkOf('E · 报错注入'));
    expect(mockOnChange).toHaveBeenCalledWith({ techniques: ['B'] });
  });

  it('tamper 勾选：追加（保持勾选顺序）', () => {
    const config = { ...DEFAULT_SQLMAP_CONFIG, tamper: ['randomcase'] };
    render(<SqlmapOptions config={config} onChange={mockOnChange} />);
    fireEvent.click(checkOf('space2comment'));
    expect(mockOnChange).toHaveBeenLastCalledWith({ tamper: ['randomcase', 'space2comment'] });
  });

  it('tamper 取消勾选：从组合中移除', () => {
    const config = { ...DEFAULT_SQLMAP_CONFIG, tamper: ['randomcase', 'space2comment'] };
    render(<SqlmapOptions config={config} onChange={mockOnChange} />);
    fireEvent.click(checkOf('space2comment'));
    expect(mockOnChange).toHaveBeenLastCalledWith({ tamper: ['randomcase'] });
  });

  it('DBMS 下拉：选择具体库写入 dbms，选「自动识别」回写 null', async () => {
    const { unmount: u1 } = render(
      <SqlmapOptions config={{ ...DEFAULT_SQLMAP_CONFIG, dbms: null }} onChange={mockOnChange} />
    );
    const trigger = screen.getByLabelText(/DBMS（留空=自动识别）/);
    fireEvent.mouseDown(trigger);
    fireEvent.click(await screen.findByRole('option', { name: 'MySQL' }));
    expect(mockOnChange).toHaveBeenCalledWith({ dbms: 'mysql' });
    u1();

    const { unmount: u2 } = render(
      <SqlmapOptions config={{ ...DEFAULT_SQLMAP_CONFIG, dbms: 'mysql' }} onChange={mockOnChange} />
    );
    const trigger2 = screen.getByLabelText(/DBMS（留空=自动识别）/);
    fireEvent.mouseDown(trigger2);
    fireEvent.click(await screen.findByRole('option', { name: '自动识别' }));
    expect(mockOnChange).toHaveBeenCalledWith({ dbms: null });
    u2();
  });

  it('破坏性操作：dump 或 fileRead 启用时显示红色警告', () => {
    const { unmount } = render(
      <SqlmapOptions config={{ ...DEFAULT_SQLMAP_CONFIG, dump: true }} onChange={mockOnChange} />
    );
    expect(screen.getByText(/已启用破坏性参数/)).toBeInTheDocument();
    unmount();

    render(
      <SqlmapOptions
        config={{ ...DEFAULT_SQLMAP_CONFIG, fileRead: '/etc/passwd' }}
        onChange={mockOnChange}
      />
    );
    expect(screen.getByText(/已启用破坏性参数/)).toBeInTheDocument();
  });

  it('无破坏性操作时不显示警告', () => {
    render(<SqlmapOptions config={DEFAULT_SQLMAP_CONFIG} onChange={mockOnChange} />);
    expect(screen.queryByText(/已启用破坏性参数/)).not.toBeInTheDocument();
  });

  it('apiClient.tampers 成功：用后端清单替换预设', async () => {
    const { apiClient } = await import('../shared/apiClient');
    (apiClient.tampers as ReturnType<typeof vi.fn>).mockResolvedValue([
      { name: 'apitamper_a' },
      { name: 'apitamper_b' },
    ]);
    render(<SqlmapOptions config={DEFAULT_SQLMAP_CONFIG} onChange={mockOnChange} />);
    expect(await screen.findByText('apitamper_a')).toBeInTheDocument();
    expect(screen.getByText('apitamper_b')).toBeInTheDocument();
    expect(screen.queryByText('space2comment')).not.toBeInTheDocument();
  });

  it('apiClient.tampers 失败：回退到内置预设清单', async () => {
    const { apiClient } = await import('../shared/apiClient');
    (apiClient.tampers as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('network down'));
    render(<SqlmapOptions config={DEFAULT_SQLMAP_CONFIG} onChange={mockOnChange} />);
    // 等待失败路径消化后，预设仍在
    await vi.waitFor(() => {
      expect(screen.getByText('space2comment')).toBeInTheDocument();
      expect(screen.getByText('versionedkeywords')).toBeInTheDocument();
    });
  });
});

// ============================================================================
// 面板 → patch 的**逐控件契约**（此前只覆盖了 8 个控件，其余 20+ 个回调从未被点过）。
//
// 为什么值得：面板类组件最高频的缺陷不是崩，而是「用户点了 A、patch 里改的是 B」
// 或「值形态错（布尔发成字符串 → 后端 `"false"` 是真值，关了等于没关）」。
// 这两类 TS 都拦不住 —— `{ flushSession: v }` 写成 `{ freshQueries: v }` 两个键都存在。
//
// ⚠️ TextField 是 `type="number"`：字母输入时 DOM value 被置空、React value tracker
// 判定"没变"、onChange 根本不触发（场景在 UI 层不存在）→ 这里只测真会发生的数值语义。
// ============================================================================
describe('SqlmapOptions · 逐控件 patch 契约', () => {
  let mockOnChange: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockOnChange = vi.fn();
    vi.clearAllMocks();
  });

  const renderWith = (over: Partial<typeof DEFAULT_SQLMAP_CONFIG> = {}) => {
    render(<SqlmapOptions config={{ ...DEFAULT_SQLMAP_CONFIG, ...over }} onChange={mockOnChange} />);
  };
  /** MUI TextField：通过 label 文本取原生 input */
  const inputOf = (label: string | RegExp) => screen.getByLabelText(label) as HTMLInputElement;
  /** MUI 开关/勾选框：FormControlLabel 的文本 → 其 input */
  const switchOf = (labelText: string | RegExp) => {
    const label = screen.getByText(labelText).closest('label');
    return label!.querySelector('input[type="checkbox"]') as HTMLInputElement;
  };
  const type = (el: HTMLInputElement, value: string) => fireEvent.change(el, { target: { value } });
  const lastPatch = () => mockOnChange.mock.calls.at(-1)?.[0] as Record<string, unknown>;

  it('retry：0 必须原样发出（后端 2026-10-03 起认 0=不重试，省略 flag 会回落默认 3 次）', () => {
    renderWith({ retry: 3 });
    const el = inputOf('重试 --retries');
    type(el, '0');
    expect(lastPatch()).toEqual({ retry: 0 });
  });

  it('retry 数值语义：负数被 Math.max 兜到 0、清空也是 0', () => {
    renderWith({ retry: 3 });
    const el = inputOf('重试 --retries');
    type(el, '-2');
    expect(lastPatch()).toEqual({ retry: 0 });
    type(el, '');
    expect(lastPatch()).toEqual({ retry: 0 });
    type(el, '7');
    expect(lastPatch()).toEqual({ retry: 7 });
  });

  it('timeoutMs：毫秒数值透传（清空/0 → 0，由后端决定是否忽略）', () => {
    renderWith();
    const el = inputOf('请求超时 (毫秒)');
    type(el, '15000');
    expect(lastPatch()).toEqual({ timeoutMs: 15000 });
    type(el, '');
    expect(lastPatch()).toEqual({ timeoutMs: 0 });
  });

  it('unionChar：只留首字符（后端仅收单字符 [A-Za-z0-9]）', () => {
    renderWith();
    const el = inputOf('--union-char');
    type(el, 'ab');
    expect(lastPatch()).toEqual({ unionChar: 'a' });
    type(el, ' ');
    expect(lastPatch()).toEqual({ unionChar: null });
  });

  it('字符串类字段：trim 后空串一律回写 null（不是空串，避免后端收到 "" 与"未设置"混淆）', () => {
    renderWith();
    type(inputOf('代理地址 --proxy'), '  http://127.0.0.1:8080  ');
    expect(lastPatch()).toEqual({ proxy: 'http://127.0.0.1:8080' });
    type(inputOf('代理地址 --proxy'), '   ');
    expect(lastPatch()).toEqual({ proxy: null });

    type(inputOf('读文件 --file-read'), '  /etc/passwd ');
    expect(lastPatch()).toEqual({ fileRead: '/etc/passwd' });

    type(inputOf('--union-cols'), ' 1-15 ');
    expect(lastPatch()).toEqual({ unionCols: '1-15' });

    type(inputOf('--union-from'), ' information_schema.tables ');
    expect(lastPatch()).toEqual({ unionFrom: 'information_schema.tables' });
  });

  // ⚠️ 分两个用例：onChange 是 mock，**不会**回写 config → 同一 render 里连续改同一字段时，
  // 第二次输入的值若与 props 现值相同则 DOM 无变化、事件不触发（不是缺陷）。
  it('可空数值字段：清空 → null', () => {
    renderWith({ verbose: 6, timeSec: 30, ignoreCode: 404 });
    type(inputOf('-v (0-6)'), '');
    expect(lastPatch()).toEqual({ verbose: null });
    type(inputOf('--time-sec'), '');
    expect(lastPatch()).toEqual({ timeSec: null });
    type(inputOf('--ignore-code'), '');
    expect(lastPatch()).toEqual({ ignoreCode: null });
  });

  it('可空数值字段：有值 → 数字（不是字符串）', () => {
    renderWith(); // 默认 null ⇒ 字段为空，输入非空值必触发 change
    type(inputOf('-v (0-6)'), '6');
    expect(lastPatch()).toEqual({ verbose: 6 });
    type(inputOf('--time-sec'), '30');
    expect(lastPatch()).toEqual({ timeSec: 30 });
    type(inputOf('--ignore-code'), '404');
    expect(lastPatch()).toEqual({ ignoreCode: 404 });
  });

  it('每个布尔开关：patch 的值必须是 boolean（字符串 "false" 在后端是真值 → 关了等于没关）', () => {
    renderWith();
    const cases: Array<[string, string]> = [
      ['随机 UA --random-agent', 'randomUA'],
      ['拖库 --dump', 'dump'],
      ['OS Shell --os-shell', 'osShell'],
      ['--exclude-sysdbs', 'excludeSysdbs'],
      ['--flush-session', 'flushSession'],
      ['--fresh-queries', 'freshQueries'],
      ['--smart', 'smart'],
      ['--no-cast', 'noCast'],
      ['--hex', 'hex'],
      ['--no-escape', 'noEscape'],
    ];
    for (const [label, key] of cases) {
      mockOnChange.mockClear();
      fireEvent.click(switchOf(label));
      const patch = lastPatch();
      expect(Object.keys(patch), `${label} 应只写 ${key}`).toEqual([key]);
      expect(typeof patch[key], `${label} 的值必须是 boolean`).toBe('boolean');
    }
  });
});

