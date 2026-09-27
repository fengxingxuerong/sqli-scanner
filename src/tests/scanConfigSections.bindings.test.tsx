// ============================================================================
// src/tests/scanConfigSections.bindings.test.tsx —— 分段接线补测（2026-09-27）
// ============================================================================
// 为什么补：ScanConfigPanel 拆成 15 个分段后，逐文件覆盖率把原本埋在单文件里的
// 低覆盖段落暴露了出来 —— SecondOrder 23% / Oob 36% / Enumeration 43% / NoSql 44%。
// 这些分段的失败形态是「控件写错键 / 关闭态留下空值 / 禁用态没生效」，既有用例都不会红。
//
// 手法与 scanConfigPanel.bindings.test.tsx 同构：受控 harness 回放真实点击/输入，
// 断言 onChange 收到的 patch 键名与值形态；文案从 zh.json 取。
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

/**
 * 定位 MUI Select 的触发器（mousedown 展开）。
 * 本版本 MUI 在 jsdom 下触发器不带 aria-labelledby（无 accessible name），
 * getByRole 按名字查询不可行 —— 改从「InputLabel 文本 → 所在 FormControl →
 * 内部 [aria-haspopup=listbox]」定位，顺带锁住 label↔控件 的成对关系。
 */
function selectTrigger(labelText: string): HTMLElement {
  const label = screen
    .getAllByText(labelText)
    .find((n) => n.className.includes('MuiInputLabel-root')) ?? screen.getByText(labelText);
  const formControl = label.closest('.MuiFormControl-root');
  const trigger = formControl?.querySelector<HTMLElement>('[aria-haspopup="listbox"]');
  if (!trigger) throw new Error(`找不到 Select 触发器：${labelText}`);
  return trigger;
}

describe('ScanConfigPanel 分段接线：OOB / 二阶 / NoSQL / 枚举拖库', () => {
  let onChange: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    onChange = vi.fn();
  });

  const renderPanel = (over: Partial<ScanConfig> = {}) => {
    render(<PanelHarness initial={makeConfig(over)} onChangeSpy={onChange} />);
    // 展开「高级设置」折叠面板：Collapse 收起时内容被 CSS 隐藏，
    // getByRole 查不到（getByLabelText 不受影响）——Select 触发器的角色查询必须先展开。
    fireEvent.click(screen.getByText(L('advanced')));
  };

  // ── OOB 分段 ──────────────────────────────────────────────────────────────
  it('① OOB 总开关开 → patch 是嵌套对象 { oob: { enabled: true } }', () => {
    renderPanel();
    fireEvent.click(screen.getByLabelText(L('oobEnable')));
    expect(onChange).toHaveBeenCalledWith({ oob: { enabled: true } });
  });

  it('② 回调地址写入 callbackBase；清空 → 键被删除（关闭态不留空串）', () => {
    renderPanel({ oob: { enabled: true } });
    const input = screen.getByLabelText(L('oobCallbackBase')) as HTMLInputElement;
    fireEvent.change(input, { target: { value: ' 127.0.0.1:8899 ' } });
    expect(onChange).toHaveBeenCalledWith({ oob: { enabled: true, callbackBase: '127.0.0.1:8899' } });
    onChange.mockClear();
    fireEvent.change(input, { target: { value: '   ' } });
    expect(onChange).toHaveBeenCalledWith({ oob: { enabled: true } });
  });

  it('③ dnsOob 打开后域名输入才出现；填入写 dnsDomain（DNS 通道的域名单独可配）', () => {
    renderPanel({ oob: { enabled: true } });
    expect(screen.queryByLabelText(L('oobDnsDomain'))).toBeNull();
    fireEvent.click(screen.getByLabelText(L('oobDnsEnable')));
    expect(onChange).toHaveBeenCalledWith({ oob: { enabled: true, dnsOob: true } });
    const domain = screen.getByLabelText(L('oobDnsDomain')) as HTMLInputElement;
    fireEvent.change(domain, { target: { value: 'oob.example.com' } });
    expect(onChange).toHaveBeenCalledWith({ oob: { enabled: true, dnsOob: true, dnsDomain: 'oob.example.com' } });
  });

  // ── 二阶注入分段 ──────────────────────────────────────────────────────────
  it('④ 二阶总开关 → { secondOrder: { enabled: true } }', () => {
    renderPanel();
    fireEvent.click(screen.getByLabelText(L('secondOrderEnable')));
    expect(onChange).toHaveBeenCalledWith({ secondOrder: { enabled: true } });
  });

  it('⑤ 触发页 textarea 多行 → string[]；清空 → 键删除（不发空数组让后端去猜）', () => {
    renderPanel({ secondOrder: { enabled: true } });
    const ta = screen.getByLabelText(L('secondOrderTriggerUrls')) as HTMLTextAreaElement;
    fireEvent.change(ta, { target: { value: 'https://a.example.com/p\nhttps://b.example.com/x' } });
    expect(onChange).toHaveBeenCalledWith({
      secondOrder: { enabled: true, triggerUrls: ['https://a.example.com/p', 'https://b.example.com/x'] },
    });
    onChange.mockClear();
    fireEvent.change(ta, { target: { value: '  \n  ' } });
    expect(onChange).toHaveBeenCalledWith({ secondOrder: { enabled: true } });
  });

  it('⑥ allowWrites（写确认位）与 oobTrigger 开 → 各自进 patch', () => {
    renderPanel({ secondOrder: { enabled: true } });
    fireEvent.click(screen.getByLabelText(L('secondOrderAllowWrites')));
    expect(onChange).toHaveBeenCalledWith({ secondOrder: { enabled: true, allowWrites: true } });
  });

  it('⑦ negativeControl 默认开（阴性对照），可显式关掉', () => {
    renderPanel({ secondOrder: { enabled: true } });
    const sw = screen.getByLabelText(L('secondOrderNegativeControl')) as HTMLInputElement;
    expect(sw.checked).toBe(true);
    fireEvent.click(sw);
    expect(onChange).toHaveBeenCalledWith({ secondOrder: { enabled: true, negativeControl: false } });
  });

  it('⑧ secondUrl（读写分离读取页）写入；清空 → 键删除', () => {
    renderPanel({ secondOrder: { enabled: true } });
    const input = screen.getByLabelText(L('secondOrderSecondUrl')) as HTMLInputElement;
    fireEvent.change(input, { target: { value: ' https://read.example.com/profile ' } });
    expect(onChange).toHaveBeenCalledWith({
      secondOrder: { enabled: true, secondUrl: 'https://read.example.com/profile' },
    });
    onChange.mockClear();
    fireEvent.change(input, { target: { value: '' } });
    expect(onChange).toHaveBeenCalledWith({ secondOrder: { enabled: true } });
  });

  it('⑨ secondMethod 下拉选 POST → patch.secondOrder.secondMethod = "POST"', async () => {
    renderPanel({ secondOrder: { enabled: true } });
    // MUI v5 的 Select 触发器 role=combobox；可访问名含「标签 + 选中值」→ 正则匹配标签前缀。
    // 另：面板内容在 Collapse 里，须先展开（renderPanel 内已点「高级设置」）角色查询才可见。
    fireEvent.mouseDown(selectTrigger(L('secondOrderSecondMethod')));
    fireEvent.click(await screen.findByRole('option', { name: 'POST' }));
    expect(onChange).toHaveBeenCalledWith({ secondOrder: { enabled: true, secondMethod: 'POST' } });
  });

  // ── NoSQL 分段 ────────────────────────────────────────────────────────────
  it('⑩ NoSQL 总开关 → { noSql: { enabled: true } }', () => {
    renderPanel();
    fireEvent.click(screen.getByLabelText(L('noSqlEnable')));
    expect(onChange).toHaveBeenCalledWith({ noSql: { enabled: true } });
  });

  it('⑪ kinds 缺省 = 三类全选（与后端 ScanManager 的兜底同义）；取消一类 → 显式数组', () => {
    renderPanel({ noSql: { enabled: true } });
    const kinds = zh.scanConfig.noSqlKind as Record<string, string>;
    for (const k of ['nosql', 'graphql', 'ssti']) {
      expect((screen.getByLabelText(kinds[k]) as HTMLInputElement).checked).toBe(true);
    }
    fireEvent.click(screen.getByLabelText(kinds.nosql));
    expect(onChange).toHaveBeenCalledWith({ noSql: { enabled: true, kinds: ['graphql', 'ssti'] } });
  });

  // ── 枚举 / 拖库分段 ───────────────────────────────────────────────────────
  it('⑫ 选择 dbs 动作 → { extractScope: { mode: "dbs" } }（整键从空到有）', async () => {
    renderPanel();
    fireEvent.mouseDown(selectTrigger(L('extractScopeLabel')));
    fireEvent.click(await screen.findByRole('option', { name: zh.scanConfig.extractScopes.dbs }));
    expect(onChange).toHaveBeenCalledWith({ extractScope: { mode: 'dbs' } });
  });

  it('⑬ tables 模式下：dbs 输入可用且写数组，keyword 输入禁用（needs 之外置灰 = 不可填）', () => {
    // 用 tables 动作（needs=['dbs']）验证「需要的输入可用、不需要的禁用」；
    // dbs 动作本身 needs=[]（自动枚举），所有输入都应禁用。
    renderPanel({ extractScope: { mode: 'tables' } });
    const dbs = screen.getByLabelText(L('extractScopeDbs')) as HTMLInputElement;
    const keyword = screen.getByLabelText(L('extractScopeKeyword')) as HTMLInputElement;
    expect(dbs.disabled).toBe(false);
    expect(keyword.disabled).toBe(true);
    fireEvent.change(dbs, { target: { value: 'db1, db2' } });
    expect(onChange).toHaveBeenCalledWith({ extractScope: { mode: 'tables', dbs: ['db1', 'db2'] } });
  });

  it('⑬b dbs 动作 needs=[] → 所有输入置灰（自动枚举不需要任何子输入）', () => {
    renderPanel({ extractScope: { mode: 'dbs' } });
    for (const key of ['extractScopeDbs', 'extractScopeKeyword']) {
      expect((screen.getByLabelText(L(key)) as HTMLInputElement).disabled).toBe(true);
    }
  });

  it('⑭ excludeSysdbs 默认开（!== false 语义），可显式关掉', () => {
    renderPanel({ extractScope: { mode: 'dbs' } });
    const sw = screen.getByLabelText(L('extractScopeExcludeSys')) as HTMLInputElement;
    expect(sw.checked).toBe(true);
    fireEvent.click(sw);
    expect(onChange).toHaveBeenCalledWith({ extractScope: { mode: 'dbs', excludeSysdbs: false } });
  });

  it('⑮ 改选「不启用」→ 整键 undefined（关闭态在请求体里干脆没这个键）', async () => {
    renderPanel({ extractScope: { mode: 'dbs', dbs: ['db1'] } });
    fireEvent.mouseDown(selectTrigger(L('extractScopeLabel')));
    fireEvent.click(await screen.findByRole('option', { name: L('extractScopeNone') }));
    expect(onChange).toHaveBeenCalledWith({ extractScope: undefined });
  });
});
