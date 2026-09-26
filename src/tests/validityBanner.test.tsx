// ValidityBanner 专属测试（此前该文件 0 覆盖，48 条语句全未执行）
// ============================================================================
// 为什么补这一份：本组件是**结论可信度守卫的 UI 出口** —— 「被封 / 目标不可达 /
// 会话失效 / 目标 5xx」时，它是用户唯一能看到的提示。它不判定、只消费
// （server/src/core/scanValidityGuard.js 产出 report.validity / summary.verdict）。
//
// 改坏它的后果不报错、只让交付物自相矛盾：
//   · 「结论不可信」被渲染成绿色成功语义 → 用户把「没测出来」读成「安全」（最贵的一类错）
//   · reliable=false 的阴性结论被当成可信 → 同上
//   · 旧报告（无 verdict/validity）被强行渲染横幅 → 向后兼容破裂
//
// 分两层测：
//   §A resolveValidityMode —— 纯函数，四分支 + 兼容推断分支逐条钉住（含边界）
//   §B 渲染 —— 三种 mode 的语义差异必须体现在 severity 与文案上（不是只看"渲染出来了"）
// ============================================================================
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import ValidityBanner, {
  resolveValidityMode,
  VALIDITY_STATUS_LABEL_KEY,
} from '../components/ValidityBanner';
import type { ReportModel, ScanValidity } from '../shared/types';

/** 最小可信度摘要（字段齐全，便于按用例覆盖单点） */
function validity(over: Partial<ScanValidity> = {}): ScanValidity {
  return {
    status: 'blocked',
    reliable: false,
    reason: '窗口内拦截特征命中 12 次（占比 60%）',
    counts: { total: 20, failStreak: 0, blockHits: 12, serverErr: 0, authLostHits: 0 },
    blockRatio: 0.6,
    suggestBackoffMs: null,
    inconclusivePoints: ['p1', 'p2'],
    advice: '建议换用 tamper 链或降速后复扫',
    ...over,
  };
}

/** 最小报告（只填 resolveValidityMode 会读的字段） */
function report(over: Partial<ReportModel> = {}): ReportModel {
  return {
    scanId: 's1',
    target: { baseUrl: 'http://t/' },
    startedAt: '2026-09-26T00:00:00Z',
    finishedAt: null,
    dbms: null,
    points: [],
    vulns: [],
    data: null,
    riskLevel: 'Low',
    summary: {},
    ...over,
  } as ReportModel;
}

const vuln = { id: 'v1' } as ReportModel['vulns'][number];

// ─────────────────────────────────────────────────────────────────────────────
describe('§A resolveValidityMode · 纯判定', () => {
  it('A1 空报告 / 无 verdict 无 validity → null（旧报告不渲染任何横幅）', () => {
    expect(resolveValidityMode(null)).toBeNull();
    expect(resolveValidityMode(undefined)).toBeNull();
    // 旧引擎报告：既无 summary.verdict 也无 validity ⇒ 向后兼容必须返回 null
    expect(resolveValidityMode(report())).toBeNull();
    // ⚠️ 等价变异记录（2026-09-26 实测，勿误判为断言缺口）：
    // 删掉实现里的短路行 `if (!validity && !verdict) return null;` 后，本用例**仍绿**。
    // 已用 17 组输入逐一比对两版输出（差异 0）⇒ 末尾 `if (validity)` + `return null` 兜住了
    // 同一语义，该短路行是**冗余但更可读**的早期退出，不是可观测判据。
    // 故此处不为它编造断言（编了也是测实现细节，不是测语义）。
  });

  it('A2 verdict=inconclusive → inconclusive（无视漏洞数与 reliable）', () => {
    // 这是「结论不可信」的唯一入口，优先级最高：即便有漏洞也必须是 inconclusive
    expect(resolveValidityMode(report({ summary: { verdict: 'inconclusive' } }))).toBe('inconclusive');
    expect(
      resolveValidityMode(
        report({ summary: { verdict: 'inconclusive', validity: validity() }, vulns: [vuln] })
      )
    ).toBe('inconclusive');
    // reliable=true 也压不住 verdict（判据以引擎结论为准，不由前端二次推断）
    expect(
      resolveValidityMode(
        report({ summary: { verdict: 'inconclusive', validity: validity({ reliable: true }) } })
      )
    ).toBe('inconclusive');
  });

  it('A3 verdict=no_vulnerability_detected 且 0 漏洞 → negative', () => {
    expect(
      resolveValidityMode(
        report({ summary: { verdict: 'no_vulnerability_detected', validity: validity({ reliable: true }) } })
      )
    ).toBe('negative');
  });

  it('A4 verdict=no_vulnerability_detected 且有漏洞 → reliable 才 hit，否则 null', () => {
    // 引擎语义：有漏洞时 verdict 恒为 no_vulnerability_detected，只有 reliable 才提示 info
    expect(
      resolveValidityMode(
        report({
          summary: { verdict: 'no_vulnerability_detected', validity: validity({ reliable: true }) },
          vulns: [vuln],
        })
      )
    ).toBe('hit');
    // reliable=false ⇒ 不渲染（null），而不是误报成 hit
    expect(
      resolveValidityMode(
        report({
          summary: { verdict: 'no_vulnerability_detected', validity: validity({ reliable: false }) },
          vulns: [vuln],
        })
      )
    ).toBeNull();
  });

  it('A5 无 verdict 走 validity 兼容推断（老报告）：negative / inconclusive / hit / null 四支', () => {
    // 0 漏洞 + reliable → negative
    expect(resolveValidityMode(report({ validity: validity({ reliable: true }) }))).toBe('negative');
    // 0 漏洞 + 不可靠 → inconclusive（关键：不可靠的阴性必须降级成「结论不可信」）
    expect(resolveValidityMode(report({ validity: validity({ reliable: false }) }))).toBe('inconclusive');
    // 有漏洞 + reliable → hit
    expect(resolveValidityMode(report({ validity: validity({ reliable: true }), vulns: [vuln] }))).toBe('hit');
    // 有漏洞 + 不可靠 → null
    expect(resolveValidityMode(report({ validity: validity({ reliable: false }), vulns: [vuln] }))).toBeNull();
  });

  it('A6 report.validity 优先于 summary.validity（顶层覆盖摘要）', () => {
    // 顶层 reliable=true、摘要 reliable=false ⇒ 走顶层 ⇒ hit
    expect(
      resolveValidityMode(
        report({ validity: validity({ reliable: true }), summary: { validity: validity({ reliable: false }) }, vulns: [vuln] })
      )
    ).toBe('hit');
  });

  it('A7 verdict=no_vulnerability_detected 但无 validity：0 漏洞仍 negative，有漏洞则 null', () => {
    // 边界：缺 validity 时不能抛错；negative 分支不依赖 validity
    expect(resolveValidityMode(report({ summary: { verdict: 'no_vulnerability_detected' } }))).toBe('negative');
    expect(
      resolveValidityMode(report({ summary: { verdict: 'no_vulnerability_detected' }, vulns: [vuln] }))
    ).toBeNull();
  });

  it('A8 vulns 字段缺失（undefined）按 0 漏洞处理，不抛错', () => {
    const r = report({ validity: validity({ reliable: true }) });
    delete (r as { vulns?: unknown }).vulns;
    expect(resolveValidityMode(r)).toBe('negative');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
describe('§B 渲染 · 语义必须体现在 severity 与文案上', () => {
  it('B1 inconclusive → warning 级，且带状态标签 / reason / 未完成点数 / 处置建议', () => {
    render(<ValidityBanner report={report({ summary: { verdict: 'inconclusive', validity: validity() } })} />);

    // 标题必须明说「不可信」——这是全组件最重要的一句话
    expect(screen.getByText('结论不可信')).toBeInTheDocument();
    // 状态标签（blocked → 疑似被 WAF/封禁），走 i18n 映射表而非硬编码
    expect(screen.getByText('疑似被 WAF/封禁')).toBeInTheDocument();
    expect(screen.getByText('窗口内拦截特征命中 12 次（占比 60%）')).toBeInTheDocument();
    // 未完成点数：用 inconclusivePoints.length（2），不是 counts.total
    expect(screen.getByText('2 个注入点未完成有效检测')).toBeInTheDocument();
    expect(screen.getByText(/建议换用 tamper 链或降速后复扫/)).toBeInTheDocument();
    // severity 判据：MUI Alert 把 severity 写进 class，别只断言"渲染出来了"
    expect(document.querySelector('.MuiAlert-root')).toHaveClass('MuiAlert-colorWarning');
  });

  it('B2 negative → info 级，文案必须显式否掉「安全」语义（不得是 success）', () => {
    render(
      <ValidityBanner
        report={report({ summary: { verdict: 'no_vulnerability_detected', validity: validity({ reliable: true }) } })}
      />
    );

    const alert = document.querySelector('.MuiAlert-root')!;
    expect(alert).toHaveClass('MuiAlert-colorInfo');
    // 硬判据：绝不允许绿色成功语义
    expect(alert).not.toHaveClass('MuiAlert-colorSuccess');
    // 文案里必须出现「不代表『安全』」这类否证 —— 这是该分支存在的全部理由
    expect(screen.getByText(/不代表「安全」/)).toBeInTheDocument();
  });

  it('B3 hit → info 级，带实测总请求数；无 suggestBackoffMs 时不渲染退避行', () => {
    render(
      <ValidityBanner
        report={report({
          summary: { verdict: 'no_vulnerability_detected', validity: validity({ reliable: true }) },
          vulns: [vuln],
        })}
      />
    );

    expect(document.querySelector('.MuiAlert-root')).toHaveClass('MuiAlert-colorInfo');
    expect(screen.getByText(/累计 20 次请求/)).toBeInTheDocument();
    expect(screen.queryByText(/Retry-After/)).toBeNull();
  });

  it('B4 hit 且 suggestBackoffMs 非 null → 追加退避建议行', () => {
    render(
      <ValidityBanner
        report={report({
          summary: {
            verdict: 'no_vulnerability_detected',
            validity: validity({ reliable: true, suggestBackoffMs: 1500 }),
          },
          vulns: [vuln],
        })}
      />
    );
    expect(screen.getByText(/1500ms/)).toBeInTheDocument();
  });

  it('B5 suggestBackoffMs=0 是合法值，不得被当成"未配置"吞掉', () => {
    // 0 与 null 语义不同：null=目标没返 Retry-After，0=返了但值为 0。
    // 实现用 `!= null` 正是为了保住这个区别（用真值判断会吞掉 0）。
    render(
      <ValidityBanner
        report={report({
          summary: { verdict: 'no_vulnerability_detected', validity: validity({ reliable: true, suggestBackoffMs: 0 }) },
          vulns: [vuln],
        })}
      />
    );
    expect(screen.getByText(/0ms/)).toBeInTheDocument();
  });

  it('B6 mode 为 null 时整个组件不渲染（向后兼容）', () => {
    const { container } = render(<ValidityBanner report={report()} />);
    expect(container.firstChild).toBeNull();
    expect(document.querySelector('.MuiAlert-root')).toBeNull();
  });

  it('B7 inconclusive 但缺 validity：只渲染标题，不崩（chip/reason 段整体跳过）', () => {
    render(<ValidityBanner report={report({ summary: { verdict: 'inconclusive' } })} />);
    expect(screen.getByText('结论不可信')).toBeInTheDocument();
    expect(screen.queryByText(/处置建议/)).toBeNull();
  });

  it('B8 五种 status 都能映射到 i18n 键（映射表无缺项，防新增 status 时漏配）', () => {
    const statuses: ScanValidity['status'][] = ['ok', 'blocked', 'unreachable', 'session_expired', 'target_error'];
    expect(Object.keys(VALIDITY_STATUS_LABEL_KEY).sort()).toEqual([...statuses].sort());
    const zh: Record<string, string> = {
      ok: '可信度正常', blocked: '疑似被 WAF/封禁', unreachable: '目标不可达',
      session_expired: '会话已失效', target_error: '目标持续 5xx',
    };
    for (const s of statuses) {
      // 每个键都必须真能在 i18n 里取到文案（不是指向不存在的键 → 界面显示原始 key）
      expect(VALIDITY_STATUS_LABEL_KEY[s]).toBe(`report.validity.status.${s}`);
      const { unmount } = render(
        <ValidityBanner report={report({ summary: { verdict: 'inconclusive', validity: validity({ status: s }) } })} />
      );
      expect(screen.getByText(zh[s])).toBeInTheDocument();
      // 用 unmount 而不是手删 DOM —— 手动 remove 会与 setup 里的 cleanup() 抢节点
      unmount();
    }
  });
});
