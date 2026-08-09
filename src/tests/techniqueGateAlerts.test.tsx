import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import TechniqueGateAlerts from '../components/TechniqueGateAlerts';
import { DEFAULT_CONFIG } from '../shared/constants';
import type { ScanConfig } from '../shared/types';

function cfg(p: Partial<ScanConfig>): ScanConfig {
  return { ...DEFAULT_CONFIG, ...p } as ScanConfig;
}

describe('TechniqueGateAlerts 技术门控前置校验（统一收口组件）', () => {
  it('scope=secondOrder：oobTrigger 开 + 接收端未启用 → 显示 info 提示', () => {
    render(
      <TechniqueGateAlerts
        config={cfg({
          secondOrder: { enabled: true, triggerUrls: [], refreshCsrf: true, negativeControl: true, oobTrigger: true },
          oob: { enabled: false, callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 5000 },
        })}
        scope="secondOrder"
      />,
    );
    expect(screen.getByText(/oobTrigger 已开启，但 OOB 接收端未启用/)).toBeTruthy();
  });

  it('scope=secondOrder：oobTrigger 开 + 接收端已启用 → 无提示', () => {
    render(
      <TechniqueGateAlerts
        config={cfg({
          secondOrder: { enabled: true, triggerUrls: [], refreshCsrf: true, negativeControl: true, oobTrigger: true },
          oob: { enabled: true, callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 5000 },
        })}
        scope="secondOrder"
      />,
    );
    expect(screen.queryByText(/oobTrigger 已开启，但 OOB 接收端未启用/)).toBeNull();
  });

  it('scope=oob：勾选 oob 技术 + 接收端未启用 → 显示 info 提示', () => {
    render(
      <TechniqueGateAlerts
        config={cfg({
          techniques: ['oob'],
          oob: { enabled: false, callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 5000 },
        })}
        scope="oob"
      />,
    );
    expect(screen.getByText(/已勾选「带外注入\(OOB\)」技术，但接收端未启用/)).toBeTruthy();
  });

  it('scope=oob：勾选 oob + 接收端启用 + risk<3 → 显示 warning 门控提示', () => {
    render(
      <TechniqueGateAlerts
        config={cfg({
          techniques: ['oob'],
          risk: 2,
          oob: { enabled: true, callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 5000 },
        })}
        scope="oob"
      />,
    );
    expect(screen.getByText(/OOB 带外需风险等级 risk≥3，当前 risk=/)).toBeTruthy();
  });

  it('scope=oob：勾选 oob + 接收端启用 + risk≥3 → 无提示', () => {
    render(
      <TechniqueGateAlerts
        config={cfg({
          techniques: ['oob'],
          risk: 3,
          oob: { enabled: true, callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 5000 },
        })}
        scope="oob"
      />,
    );
    expect(screen.queryByText(/OOB 带外需风险等级 risk≥3，当前 risk=/)).toBeNull();
  });

  it('scope 隔离：secondOrder 区块不渲染 oob 风险门控提示（防跨区块重复）', () => {
    // 触发 oob risk-gate 的全部条件，但 scope 传 secondOrder：该规则属 scope=oob，不应出现
    render(
      <TechniqueGateAlerts
        config={cfg({
          techniques: ['oob'],
          risk: 1,
          oob: { enabled: true, callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 5000 },
          secondOrder: { enabled: true, triggerUrls: [], refreshCsrf: true, negativeControl: true, oobTrigger: false },
        })}
        scope="secondOrder"
      />,
    );
    expect(screen.queryByText(/OOB 带外需风险等级 risk≥3/)).toBeNull();
  });

  it('无任何门控命中 → 返回 null（不渲染任何 Alert）', () => {
    const { container } = render(
      <TechniqueGateAlerts config={cfg({ techniques: ['boolean'], risk: 1 })} scope="oob" />,
    );
    expect(container.querySelector('.MuiAlert-root')).toBeNull();
  });
});
