import { describe, it, expect, vi, afterEach, beforeAll } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import {
  getEventStyle,
  renderSecondary,
  formatEvents,
  secondsBetween,
  computeStageTimings,
  computeBadges,
  copyText,
} from '../components/progress/progressUtils';
import i18n from '../i18n';
import type { ScanEvent } from '../shared/types';

const t = i18n.t.bind(i18n);

function ev(type: string, ts: string, payload?: unknown): ScanEvent {
  return { type, ts, payload } as ScanEvent;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('progressUtils.getEventStyle', () => {
  it('已知类型返回配置色，未知类型回退灰色默认', () => {
    expect(getEventStyle('detection_found').color).toBe('#2e7d32');
    expect(getEventStyle('waf_detected').color).toBe('#dc2626');
    expect(getEventStyle('no-such-type')).toEqual({
      icon: expect.anything(),
      color: '#757575',
    });
  });
});

describe('progressUtils.renderSecondary', () => {
  it('http_request 渲染 method url status（含 ms 时附耗时）', () => {
    const withMs = renderSecondary(
      ev('http_request', 't', { method: 'GET', url: '/a?id=1', status: 200, ms: 123 }),
      t
    );
    render(<>{withMs}</>);
    expect(screen.getByText(/GET \/a\?id=1 → 200 \(123ms\)/)).toBeInTheDocument();

    const noMs = renderSecondary(
      ev('http_request', 't', { method: 'POST', url: '/b', status: 403 }),
      t
    );
    render(<>{noMs}</>);
    expect(screen.getByText(/POST \/b → 403$/)).toBeInTheDocument();
  });

  it('sqlmap_log 按 level 着色渲染文本，未知 level 回退 output 色', () => {
    render(<>{renderSecondary(ev('sqlmap_log', 't', { level: 'warn', text: 'heavily dynamic' }), t)}</>);
    expect(screen.getByText('heavily dynamic')).toBeInTheDocument();
    expect(screen.getByText('heavily dynamic')).toHaveStyle({ color: '#ed6c02' });

    render(<>{renderSecondary(ev('sqlmap_log', 't', { text: 'plain line' }), t)}</>);
    expect(screen.getByText('plain line')).toHaveStyle({ color: '#374151' });
  });

  it('sqlmap_vuln 渲染参数与技术', () => {
    render(<>{renderSecondary(ev('sqlmap_vuln', 't', { param: 'id', technique: 'U' }), t)}</>);
    expect(screen.getByText(/发现注入点：参数/)).toBeInTheDocument();
    expect(screen.getByText('id')).toBeInTheDocument();
  });

  it('waf_detected 渲染厂商列表，无厂商时回退「未知」', () => {
    render(
      <>
        {renderSecondary(
          ev('waf_detected', 't', { vendors: [{ vendor: 'Cloudflare' }, { vendor: 'ModSecurity' }] }),
          t
        )}
      </>
    );
    expect(screen.getByText(/识别到 WAF：Cloudflare、ModSecurity/)).toBeInTheDocument();

    render(<>{renderSecondary(ev('waf_detected', 't', {}), t)}</>);
    expect(screen.getByText(/识别到 WAF：未知/)).toBeInTheDocument();
  });

  it('point_discovered 渲染候选点数量（空 points 计 0）', () => {
    render(<>{renderSecondary(ev('point_discovered', 't', { points: [1, 2, 3] }), t)}</>);
    expect(screen.getByText('发现 3 个候选注入点')).toBeInTheDocument();

    render(<>{renderSecondary(ev('point_discovered', 't', {}), t)}</>);
    expect(screen.getByText('发现 0 个候选注入点')).toBeInTheDocument();
  });

  it('其余事件：对象 payload 序列化、标量直接输出', () => {
    render(<>{renderSecondary(ev('scan_phase', 't', { phase: 'detect' }), t)}</>);
    expect(screen.getByText('{"phase":"detect"}')).toBeInTheDocument();

    render(<>{renderSecondary(ev('scan_phase', 't', 'plain'), t)}</>);
    expect(screen.getByText('plain')).toBeInTheDocument();
  });
});

describe('progressUtils.formatEvents / secondsBetween', () => {
  it('formatEvents 序列化每条事件（对象与空 payload）', () => {
    const out = formatEvents([
      ev('scan_started', '2026-01-01T00:00:00Z', { a: 1 }),
      ev('scan_phase', '2026-01-01T00:00:01Z', null),
    ]);
    expect(out).toBe(
      '[scan_started] 2026-01-01T00:00:00Z {"a":1}\n[scan_phase] 2026-01-01T00:00:01Z '
    );
  });

  it('secondsBetween：非法时间返回 0，负差值截为 0', () => {
    expect(secondsBetween('bad', '2026-01-01T00:00:10Z')).toBe(0);
    expect(secondsBetween('2026-01-01T00:00:10Z', 'bad')).toBe(0);
    expect(secondsBetween('2026-01-01T00:00:10Z', '2026-01-01T00:00:02Z')).toBe(0);
    expect(secondsBetween('2026-01-01T00:00:00Z', '2026-01-01T00:01:30Z')).toBe(90);
  });
});

describe('progressUtils.computeStageTimings', () => {
  it('事件不足 2 条返回空数组', () => {
    expect(computeStageTimings([ev('scan_started', 't')])).toEqual([]);
  });

  it('无检测/提取事件时仅输出总耗时', () => {
    const stages = computeStageTimings([
      ev('scan_started', '2026-01-01T00:00:00Z'),
      ev('scan_completed', '2026-01-01T00:00:30Z'),
    ]);
    expect(stages).toHaveLength(1);
    expect(stages[0].label).toBe('progress.stageTotal');
    expect(stages[0].seconds).toBe(30);
  });

  it('完整流程输出 检测/提取/总耗时 三段，零耗时阶段不输出', () => {
    const events = [
      ev('scan_started', '2026-01-01T00:00:00Z'),
      ev('point_testing', '2026-01-01T00:00:10Z'),
      ev('detection_found', '2026-01-01T00:00:40Z'),
      ev('extraction_progress', '2026-01-01T00:00:50Z'),
      ev('extraction_progress', '2026-01-01T00:01:20Z'),
      ev('scan_completed', '2026-01-01T00:01:30Z'),
    ];
    const stages = computeStageTimings(events);
    expect(stages.map((s) => s.label)).toEqual([
      'progress.stageDetect',
      'progress.stageExtract',
      'progress.stageTotal',
    ]);
    expect(stages[0].seconds).toBe(30);
    expect(stages[1].seconds).toBe(30);
    expect(stages[2].seconds).toBe(90);

    // extraction 起止相同（零耗时）→ 不进阶段列表
    const zero = computeStageTimings([
      ev('scan_started', '2026-01-01T00:00:00Z'),
      ev('extraction_progress', '2026-01-01T00:00:10Z'),
      ev('extraction_progress', '2026-01-01T00:00:10Z'),
      ev('scan_completed', '2026-01-01T00:00:20Z'),
    ]);
    expect(zero.map((s) => s.label)).toEqual(['progress.stageTotal']);
  });
});

describe('progressUtils.computeBadges', () => {
  it('按事件类型计数，命中= detection_found + sqlmap_vuln，仅保留非零徽章', () => {
    const badges = computeBadges([
      ev('point_discovered', 't'),
      ev('point_discovered', 't'),
      ev('point_testing', 't'),
      ev('detection_found', 't'),
      ev('sqlmap_vuln', 't'),
      ev('sqlmap_vuln', 't'),
      ev('scan_error', 't'),
      ev('scan_completed', 't'),
    ]);
    const byLabel = Object.fromEntries(badges.map((b) => [b.label, b.count]));
    expect(byLabel['progress.badgeDiscovered']).toBe(2);
    expect(byLabel['progress.badgeTested']).toBe(1);
    expect(byLabel['progress.badgeHits']).toBe(3);
    expect(byLabel['progress.badgeErrors']).toBe(1);
  });

  it('空事件列表返回空徽章', () => {
    expect(computeBadges([])).toEqual([]);
  });
});

describe('progressUtils.copyText', () => {
  it('优先使用 navigator.clipboard.writeText', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    await copyText('hello');
    expect(writeText).toHaveBeenCalledWith('hello');
  });

  it('无 clipboard API 时回退 textarea + execCommand', async () => {
    vi.stubGlobal('navigator', {});
    const execSpy = vi.fn();
    (document as any).execCommand = execSpy;
    const removeChildSpy = vi.spyOn(document.body, 'removeChild');

    await copyText('fallback');
    expect(execSpy).toHaveBeenCalledWith('copy');
    // 临时 textarea 已通过 body.removeChild 从 DOM 移除
    expect(removeChildSpy).toHaveBeenCalled();
    expect(document.querySelector('textarea')).toBeNull();
  });
});

// ── renderValidity（经 renderSecondary 的 scan_validity / scan_validity_abort 路径）──
//
// 为什么补这一组：`renderValidity` 未被 `export`，只能从这两个事件类型进入；而它是
// **结论可信度守卫的 UI 出口** —— 后端判定「已被 WAF 封 / 目标挂了 / 会话失效」时，
// 用户看到的唯一提示就是它。此前 0 覆盖，意味着这段文案与分支（异常状态回退、
// 中止时的未完成点数）从没被验证过。
describe('progressUtils.renderSecondary · 可信度守卫（renderValidity）', () => {
  // 语言可能被其他测试经 localStorage 改写，这里显式固定，避免用例顺序依赖
  beforeAll(async () => {
    await i18n.changeLanguage('zh');
  });

  const textOf = (el: ReactNode) => render(<>{el}</>).container.textContent || '';

  it('scan_validity（非中止）：渲染「提示 + 状态标签 + 实测原因」，且不出现中止文案', () => {
    const txt = textOf(
      renderSecondary(
        ev('scan_validity', 't', {
          status: 'blocked',
          reliable: false,
          reason: '实测拦截 12/20',
        } as never),
        t
      )
    );
    expect(txt).toContain('结论可信度提示');
    expect(txt).toContain('疑似被 WAF/封禁');
    expect(txt).toContain('：实测拦截 12/20');
    // 非中止路径不得出现中止文案
    expect(txt).not.toContain('扫描被守卫中止');
  });

  it('scan_validity_abort：切换到中止文案，并带出未完成检测的注入点数量', () => {
    const txt = textOf(
      renderSecondary(
        ev('scan_validity_abort', 't', {
          status: 'session_expired',
          reliable: false,
          reason: '连续 401',
          inconclusivePoints: ['p1', 'p2'],
        } as never),
        t
      )
    );
    expect(txt).toContain('扫描被守卫中止：结论不可信');
    expect(txt).toContain('会话已失效');
    expect(txt).toContain('：连续 401');
    expect(txt).toContain('2 个注入点未完成有效检测');
  });

  it('中止但未完成点为空：不渲染「0 个注入点」这种噪声', () => {
    const txt = textOf(
      renderSecondary(
        ev('scan_validity_abort', 't', {
          status: 'unreachable',
          reliable: false,
          reason: '连续超时',
          inconclusivePoints: [],
        } as never),
        t
      )
    );
    expect(txt).toContain('目标不可达');
    expect(txt).not.toContain('个注入点未完成');
  });

  it('未知 status 回退「可信度正常」标签（后端新增状态时不至于渲染 undefined）', () => {
    const txt = textOf(
      renderSecondary(
        ev('scan_validity', 't', { status: 'no_such_status', reliable: true, reason: '' } as never),
        t
      )
    );
    expect(txt).toContain('可信度正常');
    expect(txt).not.toContain('no_such_status');
  });

  it('reason 为空串时不渲染多余的冒号', () => {
    const txt = textOf(
      renderSecondary(
        ev('scan_validity', 't', { status: 'ok', reliable: true, reason: '' } as never),
        t
      )
    );
    expect(txt).not.toContain('：');
  });
});
