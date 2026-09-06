// T2 注入点精确指定：验证 parseInjectionMarks 解析参数值尾 `*` 标记，
// 与 TargetForm 在存在/不存在标记时的提示渲染。
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import TargetForm, { parseInjectionMarks } from '../components/TargetForm';

describe('parseInjectionMarks', () => {
  it('解析 URL 查询 / body / cookie / header 值尾 * 标记', () => {
    const marks = parseInjectionMarks({
      url: 'http://x/p?id=1*',
      bodyText: '{"id":"1*","other":"x"}',
      cookieText: '{"sid":"abc*"}',
      headerText: '{"X-FF":"1"}',
    });
    expect(marks).toEqual([
      { location: 'url', param: 'id', originalValue: '1' },
      { location: 'body', param: 'id', originalValue: '1' },
      { location: 'cookie', param: 'sid', originalValue: 'abc' },
    ]);
  });

  it('解析 URL 路径段 * 标记', () => {
    const marks = parseInjectionMarks({
      url: 'http://x/api/v1/users/1*/profile',
      bodyText: '',
      cookieText: '',
      headerText: '',
    });
    expect(marks).toEqual([{ location: 'url', param: '1', originalValue: '1' }]);
  });

  it('无标记返回空数组（含非法 JSON 容错）', () => {
    expect(
      parseInjectionMarks({ url: 'http://x/p?id=1', bodyText: '{"id":"1"}', cookieText: '', headerText: '' })
    ).toEqual([]);
    expect(
      parseInjectionMarks({ url: 'http://x/p', bodyText: '{bad json', cookieText: '', headerText: '' })
    ).toEqual([]);
  });
});

describe('TargetForm 注入点提示', () => {
  it('存在标记时展示「已标记注入点」提示', () => {
    render(
      <TargetForm
        url="http://x/p?id=1*"
        method="GET"
        bodyText={'{"id":"1*"}'}
        cookieText=""
        headerText=""
        onChange={() => undefined}
      />
    );
    expect(screen.getByText(/已标记注入点/)).toBeTruthy();
    expect(screen.getByText(/url\.id、body\.id/)).toBeTruthy();
  });

  it('无标记时展示引导提示文案', () => {
    render(
      <TargetForm
        url="http://x/p?id=1"
        method="GET"
        bodyText=""
        cookieText=""
        headerText=""
        onChange={() => undefined}
      />
    );
    expect(screen.getAllByText(/在参数值末尾加/).length).toBeGreaterThan(0);
  });
});
