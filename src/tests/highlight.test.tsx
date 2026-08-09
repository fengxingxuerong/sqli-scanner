// Highlight 命中高亮组件 QA：空 query / 无匹配 / 单匹配 / 大小写不敏感 / 多匹配。
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Highlight } from '../components/Highlight';

describe('Highlight 命中高亮', () => {
  it('空 query：原样返回纯文本，不渲染 <mark>', () => {
    const { container } = render(<Highlight text="注入点 p_union" query="" />);
    expect(screen.getByText('注入点 p_union')).toBeTruthy();
    expect(container.querySelectorAll('mark').length).toBe(0);
  });

  it('query 为空白：视为无搜索，原样返回', () => {
    const { container } = render(<Highlight text="user_db" query="   " />);
    expect(screen.getByText('user_db')).toBeTruthy();
    expect(container.querySelectorAll('mark').length).toBe(0);
  });

  it('文本不含 query：原样返回，无 <mark>', () => {
    const { container } = render(<Highlight text="shop_db" query="orders" />);
    expect(screen.getByText('shop_db')).toBeTruthy();
    expect(container.querySelectorAll('mark').length).toBe(0);
  });

  it('单处匹配：命中片段被 <mark> 包裹', () => {
    const { container } = render(<Highlight text="注入点 p_union" query="union" />);
    const marks = container.querySelectorAll('mark');
    expect(marks.length).toBe(1);
    expect(marks[0].textContent).toBe('union');
    // 完整文本（含高亮片段）仍可通过 textContent 串联得到，无丢失
    expect(container.textContent).toBe('注入点 p_union');
  });

  it('大小写不敏感：query 大写命中小写文本', () => {
    const { container } = render(<Highlight text="MySQL" query="mysql" />);
    const marks = container.querySelectorAll('mark');
    expect(marks.length).toBe(1);
    expect(marks[0].textContent).toBe('MySQL');
  });

  it('多处匹配：每个匹配片段各生成一个 <mark>', () => {
    const { container } = render(<Highlight text="aXbXcXd" query="x" />);
    const marks = container.querySelectorAll('mark');
    expect(marks.length).toBe(3);
    marks.forEach((m) => expect(m.textContent).toBe('X'));
  });
});
