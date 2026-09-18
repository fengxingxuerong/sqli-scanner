// targetForm.importRequest.test.tsx —— 「从请求文件导入」（对标 sqlmap -r）的行为契约
//
// 存在理由：`handleImportRequestFile` 是 TargetForm 里唯一带 IO + 多分支的处理函数
// （取文件 → 用户取消 / 解析失败 / 解析成功 / 抛异常 四条出口），且导入结果直接决定
// **扫描目标**——URL/method/body/cookie/header 一旦填错，扫的是别的东西或扫不出东西。
// 此前 0 覆盖（coverage 实测该函数未被执行）。既有 TargetForm.test.tsx 只覆盖了
// URL 输入与方法下拉，未触及导入路径。
//
// 断言落点：onChange 实际收到的 patch（外部可见的副作用）+ 用户可见的 Alert 文案，
// 而不是组件内部 state。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import TargetForm from '../components/TargetForm';
import { tauriBridge } from '../shared/tauriBridge';
import i18n from '../i18n';

// 只桩掉「取文件」这一个动作，其余桥接能力保持真实。
// 注意：TargetForm 消费的是 **命名空间对象** `tauriBridge.openTextFile`，不是裸的具名导出——
// 直接 mock 一个 `openTextFile` 具名导出会得到 undefined，异常被组件 try/catch 吞掉，
// 表现为「点击后什么都没发生」（实测踩到）。故这里展开真实模块再覆盖单个方法。
vi.mock('../shared/tauriBridge', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../shared/tauriBridge')>();
  return {
    ...actual,
    tauriBridge: { ...actual.tauriBridge, openTextFile: vi.fn() },
  };
});

const mockedOpen = tauriBridge.openTextFile as unknown as ReturnType<typeof vi.fn>;

const RAW_GET_WITH_PARAM = [
  'GET http://example.com/item.php?id=1 HTTP/1.1',
  'Host: example.com',
  'X-Custom-Trace: abc123',
  '',
].join('\r\n');

const RAW_POST_WITH_BODY = [
  'POST /login HTTP/1.1',
  'Host: example.com',
  'Cookie: sid=abc123',
  'Content-Type: application/x-www-form-urlencoded',
  '',
  'u=1&p=2',
].join('\r\n');

function setup() {
  const onChange = vi.fn();
  render(
    <TargetForm
      url=""
      method="GET"
      bodyText=""
      cookieText=""
      headerText=""
      onChange={onChange}
    />
  );
  return { onChange };
}

const clickImport = () => fireEvent.click(screen.getByText('从请求文件导入'));

describe('TargetForm 从请求文件导入', () => {
  beforeEach(async () => {
    // 语言可能被其他测试经 localStorage 改写，显式固定避免顺序依赖
    await i18n.changeLanguage('zh');
    mockedOpen.mockReset();
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it('用户取消选择文件：不触发 onChange，也不弹提示', async () => {
    mockedOpen.mockResolvedValue(null);
    const { onChange } = setup();
    clickImport();

    await waitFor(() => expect(mockedOpen).toHaveBeenCalled());
    expect(onChange).not.toHaveBeenCalled();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('内容无法解析为 HTTP 请求：给出明确失败提示，且不污染现有表单', async () => {
    mockedOpen.mockResolvedValue('这不是一个 HTTP 请求');
    const { onChange } = setup();
    clickImport();

    expect(await screen.findByText(/请求文件解析失败/)).toBeTruthy();
    expect(onChange).not.toHaveBeenCalled();
  });

  it('取文件抛异常（桥接不可用等）：走同一失败提示，不冒泡到组件外', async () => {
    mockedOpen.mockRejectedValue(new Error('bridge down'));
    const { onChange } = setup();
    clickImport();

    expect(await screen.findByText(/请求文件解析失败/)).toBeTruthy();
    expect(onChange).not.toHaveBeenCalled();
  });

  it('解析成功且含 URL 参数：回填 url/method，提示中报出参数个数', async () => {
    mockedOpen.mockResolvedValue(RAW_GET_WITH_PARAM);
    const { onChange } = setup();
    clickImport();

    await waitFor(() => expect(onChange).toHaveBeenCalledTimes(1));
    const patch = onChange.mock.calls[0][0];
    expect(patch.url).toBe('http://example.com/item.php?id=1');
    expect(patch.method).toBe('GET');
    expect(await screen.findByText(/发现 1 个 URL 参数/)).toBeTruthy();
  });

  it('解析成功且无 URL 参数：提示不带参数计数', async () => {
    mockedOpen.mockResolvedValue(
      ['GET http://example.com/static HTTP/1.1', 'Host: example.com', ''].join('\r\n')
    );
    const { onChange } = setup();
    clickImport();

    await waitFor(() => expect(onChange).toHaveBeenCalled());
    expect(onChange.mock.calls[0][0].url).toBe('http://example.com/static');
    expect(await screen.findByText('已从请求文件导入：GET')).toBeTruthy();
    expect(screen.queryByText(/个 URL 参数/)).toBeNull();
  });

  it('导入带 body/cookie 的请求：回填三件套并自动展开高级参数区', async () => {
    mockedOpen.mockResolvedValue(RAW_POST_WITH_BODY);
    const { onChange } = setup();
    // 初始为收起态
    expect(screen.getByText('添加 Body / Cookie / Header 参数')).toBeTruthy();

    clickImport();

    await waitFor(() => expect(onChange).toHaveBeenCalled());
    const patch = onChange.mock.calls[0][0];
    expect(patch.method).toBe('POST');
    expect(patch.bodyText).toBeTruthy();
    expect(patch.cookieText).toBeTruthy();

    // 自动展开后，切换文案变为「收起高级参数」——用户无需再点一次即可核对导入内容
    expect(await screen.findByText('收起高级参数')).toBeTruthy();
  });

  it('再次导入失败时，先清掉上一次的成功提示（不残留过期状态）', async () => {
    mockedOpen.mockResolvedValueOnce(RAW_GET_WITH_PARAM);
    setup();
    clickImport();
    expect(await screen.findByText(/发现 1 个 URL 参数/)).toBeTruthy();

    mockedOpen.mockResolvedValueOnce('垃圾内容');
    clickImport();
    await waitFor(() => expect(screen.queryByText(/发现 1 个 URL 参数/)).toBeNull());
    expect(await screen.findByText(/请求文件解析失败/)).toBeTruthy();
  });
});
