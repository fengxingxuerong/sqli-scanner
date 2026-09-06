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

