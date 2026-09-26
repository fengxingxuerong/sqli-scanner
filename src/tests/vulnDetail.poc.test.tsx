// VulnDetail · PoC 复现区测试（此前 lines 81-158 整段未覆盖，文件仅 63.38%）
// ============================================================================
// 为什么补这一份：`PocSection` / `CopyBox` 是**交付五要素里「利用证明」的 UI 出口**
// （另外四要素是类型·CWE·OWASP / CVSS / 受影响参数 / 修复建议）。
// 导出报告里的 `poc.curl` 就是给工程师粘终端用的 —— 复制按钮坏了，等于交付物只能靠手抄。
//
// 改坏的后果不报错、只让交付打折：
//   · poc 缺失时渲染空白/undefined → 报告出现「有 PoC 区块但里面没东西」
//   · curl / raw 同时存在时只渲染其一 → 工程师拿不到完整复现链
//   · 剪贴板不可用（非安全上下文）时抛异常 → 整个详情页崩（注释明写"静默"是设计意图）
//
// 判据（别只看"渲染出来了"）：
//   ① poc 缺失 ⇒ 整块不渲染（不留空壳）
//   ② curl 与 raw 各自独立渲染（不是二选一）
//   ③ 剪贴板失败必须被吞掉（静默），不得冒泡成渲染异常
//   ④ 复制成功后按钮图标切换（copied 反馈），且延时后复位
// ============================================================================
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import VulnDetail from '../components/VulnDetail';
import type { Vulnerability, Target, InjectionPoint } from '../shared/types';

const { copyTextMock } = vi.hoisted(() => ({ copyTextMock: vi.fn() }));

vi.mock('../components/progress/progressUtils', async () => {
  const actual = await vi.importActual<typeof import('../components/progress/progressUtils')>(
    '../components/progress/progressUtils'
  );
  return { ...actual, copyText: copyTextMock };
});

const baseVuln: Vulnerability = {
  id: 'v1', pointId: 'p1', technique: 'union', dbms: 'MySQL', riskLevel: 'High',
  payloads: ["1' UNION SELECT 1,2,3-- -"],
  description: 'UNION 注入成功，回显列：1,2,3',
  evidence: 'UNION 注入成功（列数 3）',
  trace: null,
};

const target = {
  id: 't1', baseUrl: 'http://example.com/item.php?id=1', method: 'GET',
  bodyParams: {}, cookieParams: {}, headerParams: {},
} as unknown as Target;

const point = {
  id: 'p1', location: 'url', param: 'id', originalValue: '1',
  confirmed: true, technique: 'union', dbms: 'MySQL',
} as unknown as InjectionPoint;

function renderWith(poc: unknown) {
  return render(
    <VulnDetail vuln={{ ...baseVuln, poc } as unknown as Vulnerability} target={target} point={point} />
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  copyTextMock.mockResolvedValue(undefined);
});
afterEach(() => {
  vi.useRealTimers();
});

describe('VulnDetail · PoC 复现区', () => {
  it('P1 无 poc → 整个 PoC 区块不渲染（不留空壳）', () => {
    renderWith(undefined);
    expect(screen.queryByTestId('poc-section')).toBeNull();
  });

  it('P2 ⚠️ 实测发现：poc={} 会渲染一个只有标题的空壳 Paper（不是缺口，是登记的事实）', () => {
    // 本用例**记录当前行为**，不是断言理想行为 —— 按本仓纪律，不为未实现的语义编造断言。
    //
    // 实测：`VulnDetail.tsx:233` 的守卫是 `{vuln.poc && <PocSection poc={vuln.poc} />}`，
    // 而 `{}` 是真值 ⇒ 渲染出一个只有 h6 标题、无 curl / 无 raw / 无脚注的空 Paper。
    // 触发条件：poc 存在但三个字段全空。真实报告里 pocBuilder 不会产出这种对象，
    // 故属**低危瑕疵**（观感问题，不是判据错误）—— 记为发现，留给后续决定是否收紧为
    // `vuln.poc?.curl || vuln.poc?.raw`。
    renderWith({});
    const section = screen.getByTestId('poc-section');
    expect(section).toBeInTheDocument();
    // 空壳的判据：有标题，但没有可复制的 curl、也没有 raw 按钮
    expect(section.textContent).toContain('复现方式');
    expect(screen.queryByRole('button', { name: /复制/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /原始/ })).toBeNull();
  });

  it('P3 有 curl → 渲染等宽文本框 + 复制按钮，且 aria-label 可被无障碍读到', () => {
    renderWith({ curl: "curl -s 'http://t/?id=1%27'" });
    expect(screen.getByTestId('poc-section')).toBeInTheDocument();
    expect(screen.getByText("curl -s 'http://t/?id=1%27'")).toBeInTheDocument();
    // 复制按钮必须有可访问名（否则屏幕阅读器只念"按钮"）
    expect(screen.getByRole('button', { name: /复制/ })).toBeInTheDocument();
  });

  it('P4 curl 与 raw 同时存在 → 两者都渲染（判据②，不是二选一）', () => {
    renderWith({ curl: 'curl -s x', raw: 'GET /item.php?id=1 HTTP/1.1\nHost: example.com' });
    expect(screen.getByText('curl -s x')).toBeInTheDocument();
    // raw 在折叠区里：先确认展开按钮存在
    const rawBtn = screen.getByRole('button', { name: /原始 HTTP 报文/ });
    expect(rawBtn).toBeInTheDocument();
    // 展开后正文可见（Collapse 默认收起）。
    // 注意：同一段报文文本在「请求报文（复现）」区也会出现 ⇒ 必须限定在 poc-section 内查询，
    // 否则 getByText 会命中多个元素（这是本仓"选择器不够窄导致假失败"的常见形态）。
    fireEvent.click(rawBtn);
    const section = screen.getByTestId('poc-section');
    expect(section.textContent).toContain('GET /item.php?id=1 HTTP/1.1');
  });

  it('P5 只有 raw、无 curl → 仍渲染区块，且不出现 curl 标签', () => {
    renderWith({ raw: 'POST /x HTTP/1.1' });
    expect(screen.getByTestId('poc-section')).toBeInTheDocument();
    expect(screen.queryByText(/curl/i)).toBeNull();
  });

  it('P6 点击复制 → 调 copyText 且传入完整 curl（不是截断版）', async () => {
    const curl = "curl -s 'http://t/?id=1' -H 'X-A: b'";
    renderWith({ curl });
    fireEvent.click(screen.getByRole('button', { name: /复制/ }));
    await waitFor(() => expect(copyTextMock).toHaveBeenCalledWith(curl));
  });

  it('P7 剪贴板不可用 → 静默吞掉异常，组件不崩（判据③）', async () => {
    copyTextMock.mockRejectedValueOnce(new Error('clipboard denied (non-secure context)'));
    // ⚠️ 这条断言的敏感度边界（2026-09-26 实测记录，勿误读）：
    // 去掉实现里的 try/catch 后，本用例**仍会绿** —— 因为 onClick 不 await handleCopy，
    // 逃逸的 rejection 既不触发 window.unhandledrejection（jsdom 下实测捕获不到），
    // 也不是 React 渲染错误，而是被 vitest 的 **Unhandled Errors** 机制接走 ⇒ 套件 exit=1。
    // 也就是说：注入确实被拦住了，但拦它的是 vitest 兜底，不是这条断言。
    // 这里不编造一条"看起来在管"的断言（那正是本仓最反感的形态），改为同时钉住两件能观测的事：
    //   ① 复制失败不得让组件进入不可用状态（按钮仍可点、区块仍在）
    //   ② 失败不得被误报成"复制成功"（图标不得切到已复制态）
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      renderWith({ curl: 'curl -s x' });
      fireEvent.click(screen.getByRole('button', { name: /复制/ }));
      await waitFor(() => expect(copyTextMock).toHaveBeenCalled());
      await new Promise((r) => setTimeout(r, 30));
      // ① 组件不崩：区块仍在、按钮仍可用（用户可手动选中复制）
      expect(screen.getByTestId('poc-section')).toBeInTheDocument();
      const btn = screen.getByRole('button', { name: /复制/ });
      expect(btn).not.toBeDisabled();
      // ② 失败不得被读成成功：不得出现"已复制"的 CheckIcon（setCopied(true) 只在成功路径）
      // 注意必须**重新查询**按钮：状态更新后 React 可能换掉节点，旧引用会变成游离节点而永远"干净"
      const fresh = screen.getByRole('button', { name: /复制/ });
      expect(fresh.querySelector('[data-testid="CheckIcon"]')).toBeNull();
    } finally {
      errSpy.mockRestore();
    }
  });

  it('P8 note / generatedAt 存在时渲染脚注；缺失时不渲染', () => {
    const { unmount } = renderWith({ curl: 'curl -s x', note: '由导出路径生成', generatedAt: '2026-09-26T00:00:00Z' });
    expect(screen.getByText(/由导出路径生成/)).toBeInTheDocument();
    unmount();

    renderWith({ curl: 'curl -s x' });
    expect(screen.queryByText(/由导出路径生成/)).toBeNull();
  });

  it('P9 raw 展开/收起可切换（两次点击回到收起态）', async () => {
    renderWith({ raw: 'GET /x HTTP/1.1' });
    const btn = screen.getByRole('button', { name: /原始 HTTP 报文/ });
    fireEvent.click(btn);
    expect(screen.getByText(/GET \/x HTTP\/1\.1/)).toBeInTheDocument();
    fireEvent.click(btn);
    // MUI Collapse 默认**保留**子节点（unmountOnExit=false），仅折叠高度；
    // 且折叠有 transition ⇒ 必须 await 等动画结束，同步断言会假红（实测踩到）。
    await waitFor(() => expect(screen.getByText(/GET \/x HTTP\/1\.1/)).not.toBeVisible());
  });
});
