// T1 漏洞详情补证据与请求报文：验证 buildRequestEvidence / formatRequestEvidence 纯函数
// 与 VulnDetail 在给定 target/point 上下文时渲染「证据」与「请求报文」区块。
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import VulnDetail, { buildRequestEvidence, formatRequestEvidence } from '../components/VulnDetail';
import type { Vulnerability, Target, InjectionPoint } from '../shared/types';

const vuln: Vulnerability = {
  id: 'v1',
  pointId: 'p1',
  technique: 'union',
  dbms: 'MySQL',
  riskLevel: 'High',
  payloads: ["1' UNION SELECT 1,2,3-- -"],
  description: 'UNION 注入成功，回显列：1,2,3',
  evidence: 'UNION 注入成功，回显列：1,2,3（列数 3）',
  trace: null,
};

const target: Target = {
  id: 't1',
  baseUrl: 'http://example.com/item.php?id=1',
  method: 'GET',
  bodyParams: {},
  cookieParams: { PHPSESSID: 'abc' },
  headerParams: { 'X-Token': 'xyz' },
  config: {
    concurrency: 4,
    timeoutMs: 10000,
    retry: 2,
    timeThresholdMs: 1500,
    ratePerSec: 3,
    enableExtract: false,
    proxy: null,
    auth: null,
    wafEvasion: {
      randomUA: false,
      jitterMs: 0,
      obfuscate: false,
      tamper: { enabled: false, plugins: [], intensity: 'medium' },
    },
    techniques: ['union', 'error', 'boolean', 'time'],
  },
};

const point: InjectionPoint = {
  id: 'p1',
  location: 'url',
  param: 'id',
  originalValue: '1',
  confirmed: true,
  technique: 'union',
  dbms: 'MySQL',
};

describe('buildRequestEvidence / formatRequestEvidence', () => {
  it('由 target + point 构建方法/URL/关键头/注入点/payload 证据', () => {
    const ev = buildRequestEvidence(vuln, target, point);
    expect(ev).not.toBeNull();
    expect(ev!.method).toBe('GET');
    expect(ev!.url).toBe('http://example.com/item.php?id=1');
    expect(ev!.location).toBe('url.id');
    expect(ev!.originalValue).toBe('1');
    // 关键头 = headerParams + cookieParams（Cookie 拼接）
    expect(ev!.headers).toContainEqual(['X-Token', 'xyz']);
    expect(ev!.headers).toContainEqual(['Cookie', 'PHPSESSID=abc']);
    expect(ev!.payload).toBe("1' UNION SELECT 1,2,3-- -");
  });

  it('target 缺失时返回 null（前端兜底）', () => {
    expect(buildRequestEvidence(vuln, null, point)).toBeNull();
    expect(buildRequestEvidence(vuln, undefined, undefined)).toBeNull();
  });

  it('格式化输出含请求行/注入点/头/Payload', () => {
    const ev = buildRequestEvidence(vuln, target, point)!;
    const lines = formatRequestEvidence(ev);
    // [P0-FIX] 格式改为 HTTP 报文格式：`METHOD path HTTP/1.1` + Host + 头 + Payload
    expect(lines[0]).toBe('GET /item.php?id=1 HTTP/1.1');
    expect(lines.join('\n')).toContain('Host: example.com');
    expect(lines.join('\n')).toContain('注入点：url.id（原始值 1）');
    expect(lines.join('\n')).toContain('X-Token: xyz');
    expect(lines.join('\n')).toContain('Cookie: PHPSESSID=abc');
    expect(lines.join('\n')).toContain("Payload: 1' UNION SELECT 1,2,3-- -");
  });
});

describe('VulnDetail 证据与请求报文展示', () => {
  it('展示证据（Evidence）区块（evidence 独立于说明）', () => {
    render(<VulnDetail vuln={vuln} target={target} point={point} />);
    expect(screen.getByText('证据（Evidence）')).toBeTruthy();
    expect(screen.getByText(/回显列：1,2,3（列数 3）/)).toBeTruthy();
  });

  it('展示请求报文（复现）区块', () => {
    render(<VulnDetail vuln={vuln} target={target} point={point} />);
    expect(screen.getByText('请求报文（复现）')).toBeTruthy();
    // [P0-FIX] 格式改为 HTTP 报文：GET /item.php?id=1 HTTP/1.1
    expect(screen.getByText(/GET \/item\.php\?id=1 HTTP\/1\.1/)).toBeTruthy();
    expect(screen.getByText(/注入点：url\.id（原始值 1）/)).toBeTruthy();
  });

  it('无 target 上下文时不渲染请求报文但保留证据', () => {
    render(<VulnDetail vuln={vuln} />);
    expect(screen.queryByText('请求报文（复现）')).toBeNull();
    expect(screen.getByText('证据（Evidence）')).toBeTruthy();
  });
});
