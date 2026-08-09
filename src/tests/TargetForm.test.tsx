import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import TargetForm from '../components/TargetForm';

const BASE_PROPS = {
  url: '',
  method: 'GET' as const,
  bodyText: '',
  cookieText: '',
  headerText: '',
  onChange: () => undefined,
};

describe('TargetForm 组件', () => {
  it('渲染目标录入区与 URL 录入控件', () => {
    render(<TargetForm {...BASE_PROPS} />);
    expect(screen.getByText('目标录入')).toBeTruthy();
    // 用 placeholder 定位 URL 输入框，避开 MUI label 关联歧义
    expect(screen.getByPlaceholderText('http://example.com/item.php?id=1')).toBeTruthy();
  });

  it('修改 URL 触发 onChange 回传 { url }', () => {
    const onChange = vi.fn();
    render(<TargetForm {...BASE_PROPS} onChange={onChange} />);
    const input = screen.getByPlaceholderText('http://example.com/item.php?id=1') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'http://x/a.php?id=1' } });
    expect(onChange).toHaveBeenCalledWith({ url: 'http://x/a.php?id=1' });
  });

  it('请求方法下拉可展开并含 POST 选项', async () => {
    render(<TargetForm {...BASE_PROPS} />);
    // 默认选中 GET；点开下拉后出现 POST 选项
    expect(screen.getByText('GET')).toBeTruthy();
    fireEvent.mouseDown(screen.getByText('GET'));
    expect(await screen.findByText('POST')).toBeTruthy();
  });
});
