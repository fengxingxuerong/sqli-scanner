import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import VulnDetail from '../components/VulnDetail';
import { RISK_LABEL, TECHNIQUE_LABEL } from '../shared/constants';
import type { Vulnerability } from '../shared/types';

const stackedVuln: Vulnerability = {
  id: 'v1',
  pointId: 'p1',
  technique: 'stacked',
  dbms: 'MySQL',
  riskLevel: 'Critical',
  payloads: ["1'; SLEEP(2)-- -"],
  description: '堆叠注入确认：连续 2/3 次响应延迟 ≥ 1.5s，";" 后第二条语句被成功执行',
};

describe('F-19 堆叠注入报告呈现（QA 独立验证）', () => {
  it('堆叠漏洞详情显示技术「堆叠注入」+ 风险「严重」(红 Chip)', () => {
    render(<VulnDetail vuln={stackedVuln} />);
    // 技术标签
    expect(screen.getByText(TECHNIQUE_LABEL.stacked)).toBeTruthy();
    // 风险等级中文（Critical → 严重），Chip 文案
    expect(screen.getByText(RISK_LABEL.Critical)).toBeTruthy();
    // 命中证据说明
    expect(screen.getByText(/第二条语句被成功执行/)).toBeTruthy();
  });

  it('堆叠漏洞展示专项高危说明（非自动利用提示）', () => {
    render(<VulnDetail vuln={stackedVuln} />);
    expect(screen.getByText(/堆叠注入可进一步用于写文件/)).toBeTruthy();
  });

  it('无漏洞时不渲染详情（空态）', () => {
    render(<VulnDetail vuln={null} />);
    expect(screen.getByText('请选择左侧漏洞查看详情')).toBeTruthy();
  });
});
