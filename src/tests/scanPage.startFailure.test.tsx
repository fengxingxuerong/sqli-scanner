// ScanPage 启动失败路径补测（此前 lines 84-97 整段未覆盖）
// ============================================================================
// 为什么补这一份：`doStart` 的 catch 块是**用户唯一能看到的失败归因**。
// 它按后端错误码分派四类消息：
//   · ENGINE_BUSY   → 「引擎忙，请稍后重试」（可恢复，不该展示裸错误）
//   · RATE_LIMITED  → 「请求过于频繁」（同上）
//   · 其它 ApiError → 展示后端原始 message
//   · 非 ApiError   → 展示 e.message
// 改坏的后果不报错，只让用户拿到错误的处置方向 —— 例如把「引擎忙」显示成
// 「启动失败」，用户会去查网络而不是等一会儿（本仓把这类叫「结论看着正常、语义完全不同」）。
//
// 判据（别只看"渲染出错误了"）：
//   ① 三类可恢复/不可恢复错误必须**文案互不相同**（否则分派等于没做）
//   ② 非 ApiError 的 Error 也必须被接住（不能只处理 ApiError 就漏掉普通异常）
//   ③ 错误后 status 必须落到 'error'，且 starting 复位（否则按钮永久禁用）
// ============================================================================
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import ScanPage from '../pages/ScanPage';
import { useScanStore } from '../store/scanStore';
import { sqlmapClient, ApiError } from '../shared/apiClient';
import { ErrorCode } from '../shared/types';

const { startScanMock } = vi.hoisted(() => ({ startScanMock: vi.fn() }));

vi.mock('../hooks/useScan', () => ({
  useScan: () => ({
    startScan: startScanMock,
    stopScan: vi.fn(),
    pauseScan: vi.fn(),
    resumeScan: vi.fn(),
  }),
}));
vi.mock('../hooks/useEvents', () => ({ useEvents: vi.fn() }));

// 真实 ApiError：带 code 字段（现有 scanPage.test 把它 mock 成空壳类，故错误码分支从没被执行）
vi.mock('../shared/apiClient', async () => {
  const actual = await vi.importActual<typeof import('../shared/apiClient')>('../shared/apiClient');
  return {
    API_BASE: 'http://test/api',
    ApiError: actual.ApiError,
    apiClient: { get: vi.fn(), post: vi.fn(), tampers: vi.fn().mockResolvedValue([]) },
    exploitClient: { capabilities: vi.fn() },
    sqlmapClient: { status: vi.fn() },
  };
});

vi.mock('../shared/tauriBridge', () => ({
  tauriBridge: { startEngine: vi.fn(), stopEngine: vi.fn(), saveFile: vi.fn() },
}));

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/scan']}>
      <Routes>
        <Route path="/scan" element={<ScanPage />} />
        <Route path="/report/:id" element={<div>REPORT_PROBE</div>} />
      </Routes>
    </MemoryRouter>
  );
}

/** 填 URL → 点开始（走完 doStart 的 try 分支并进入 catch），返回错误提示文本 */
async function startWithFailure(err: unknown): Promise<string> {
  // 同一用例内可能连续调两次（对比两类错误文案）⇒ 先清上一次的 DOM，
  // 否则 findByRole('alert') 会命中残留节点，把"上一次的文案"当成"这一次的"
  cleanup();
  startScanMock.mockRejectedValueOnce(err);
  renderPage();
  // 选择器与 scanPage.test.tsx 对齐（页面上有多个同占位符输入）
  fireEvent.change(screen.getAllByPlaceholderText('http://example.com/item.php?id=1')[0], {
    target: { value: 'http://t/item.php?id=1' },
  });
  fireEvent.click(screen.getByRole('button', { name: '开始扫描' }));
  // 拖库默认开启 → 先过二次确认，才真正调 startScan（进而触发 catch）
  const confirm = screen.queryByText('我已知晓，继续');
  if (confirm) fireEvent.click(confirm);
  await waitFor(() => expect(useScanStore.getState().status).toBe('error'));
  // 错误经 ScanWizard 的 <Alert severity="error"> 渲染（ScanPage 不直接渲染）
  const alert = await screen.findByRole('alert');
  return alert.textContent ?? '';
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(sqlmapClient.status).mockResolvedValue({ available: true } as never);
  useScanStore.setState({
    scanId: null, scanEngine: null, status: 'pending', engine: 'builtin',
    report: null, events: [], history: [], wafSuggestion: null,
    progressTotal: 0, processedPointIds: {},
  });
});

describe('ScanPage · 启动失败的四类归因（lines 84-97）', () => {
  it('ENGINE_BUSY → 展示「引擎忙」专有文案，且不等于通用失败文案', async () => {
    const busyText = await startWithFailure(new ApiError(ErrorCode.ENGINE_BUSY, 'engine busy raw'));
    expect(busyText).toMatch(/忙|占用|稍后/);
    // 判据①：不得把原始错误直接抛给用户（那等于没做分派）
    expect(busyText).not.toContain('engine busy raw');
  });

  it('RATE_LIMITED → 展示限流专有文案，且与 ENGINE_BUSY 文案不同', async () => {
    const busy = await startWithFailure(new ApiError(ErrorCode.ENGINE_BUSY, 'x'));
    useScanStore.setState({ status: 'pending' });
    const limited = await startWithFailure(new ApiError(ErrorCode.RATE_LIMITED, 'y'));
    expect(limited).toMatch(/频繁|限流|稍后/);
    // 判据①：两类可恢复错误必须可区分，否则分派等于空转
    expect(limited).not.toBe(busy);
  });

  it('其它 ApiError → 透传后端原始 message（后端知道得比前端多）', async () => {
    const text = await startWithFailure(new ApiError(ErrorCode.UNKNOWN, '目标返回 502 网关错误'));
    expect(text).toContain('目标返回 502 网关错误');
  });

  it('非 ApiError 的普通 Error → 也被接住并展示其 message（判据②）', async () => {
    const text = await startWithFailure(new Error('Network request failed'));
    expect(text).toContain('Network request failed');
  });

  it('非 Error 的裸抛出 → 回落到通用失败文案，不崩、不留白', async () => {
    const text = await startWithFailure('boom');
    expect(text.trim().length).toBeGreaterThan(0);
  });

  it('失败后 status=error 且按钮复位可用（starting 必须复位，判据③）', async () => {
    await startWithFailure(new ApiError(ErrorCode.ENGINE_BUSY, 'x'));
    expect(useScanStore.getState().status).toBe('error');
    // starting 未复位 ⇒ 按钮永久 disabled，用户无法重试
    const btn = screen.getByRole('button', { name: '开始扫描' });
    expect(btn).not.toBeDisabled();
  });

  it('空 message 的 ApiError → 回落通用文案（不展示空字符串）', async () => {
    const text = await startWithFailure(new ApiError(ErrorCode.UNKNOWN, ''));
    expect(text.trim().length).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// parseForm / parseJson（lines 25-26 + parseForm 的 catch 分支）
// 为什么值得测：这三行决定「用户粘的 body/cookie/header 能不能变成注入点」。
// 判据：空文本必须归零为 {}（而不是抛错），非法 JSON 必须被拦在发起请求之前。
describe('ScanPage · 表单解析护栏（parseJson / parseForm）', () => {
  /** 展开高级设置（body 等输入在 TargetForm 的折叠区内） */
  function openAdvanced() {
    const adv = screen.getByRole('button', { name: /高级设置/ });
    fireEvent.click(adv);
  }

  it('空 body/cookie/header 文本 → 归零为 {}，且不展示 JSON 解析错误', async () => {
    cleanup();
    startScanMock.mockResolvedValueOnce('s1');
    renderPage();
    fireEvent.change(screen.getAllByPlaceholderText('http://example.com/item.php?id=1')[0], {
      target: { value: 'http://t/item.php?id=1' },
    });
    fireEvent.click(screen.getByRole('button', { name: '开始扫描' }));
    const confirm = screen.queryByText('我已知晓，继续');
    if (confirm) fireEvent.click(confirm);
    await waitFor(() => expect(startScanMock).toHaveBeenCalledTimes(1));
    const args = startScanMock.mock.calls[0][0];
    // 空文本 → {}（parseJson 的 `if (!text.trim()) return {}` 分支，lines 25-26）
    expect(args.bodyParams).toEqual({});
    expect(args.cookieParams).toEqual({});
    expect(args.headerParams).toEqual({});
    // 不得展示 JSON 解析错误（空文本是合法输入，不是错误）
    expect(screen.queryByText(/JSON 格式|格式错误|解析失败/)).toBeNull();
  });

  it('非法 JSON body → 拦在发起请求之前，展示解析错误且不调用 startScan', async () => {
    cleanup();
    renderPage();
    fireEvent.change(screen.getAllByPlaceholderText('http://example.com/item.php?id=1')[0], {
      target: { value: 'http://t/item.php?id=1' },
    });
    openAdvanced();
    // TargetForm 的 Body 参数输入（label 文案固定）
    const bodyInput = screen.getByLabelText(/Body 参数/);
    fireEvent.change(bodyInput, { target: { value: '{not valid json' } });
    fireEvent.click(screen.getByRole('button', { name: '开始扫描' }));
    // 判据：非法输入必须在发请求前被拦下（这是「注入点来自用户粘贴」的边界）
    await waitFor(() => expect(screen.getAllByRole('alert').length).toBeGreaterThan(0));
    expect(startScanMock).not.toHaveBeenCalled();
  });
});
