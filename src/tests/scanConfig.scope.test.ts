// scanConfig.scope.test.ts —— 授权范围（scope）相关纯函数的行为契约
//
// 为什么单独测：scope 是「渗透第一红线」。UI 里它只是一个多行文本框，真正的语义由
// parseScopeList / normalizeScanValue(stringArray) / buildResumeConfig 三个纯函数决定——
// 解析错一个分隔符，就等于把「限定的授权范围」变成「不限制」或「范围写错」，
// 后果是**越权扫描**。这类函数必须有独立契约测试，不能只靠面板的渲染测试顺带覆盖。
//
// 覆盖目标（此前覆盖率报告标出的未覆盖分支）：
//   · parseScopeList 全分支；
//   · normalizeScanValue 的 stringArray 容错分支（逗号串 → 数组）；
//   · buildResumeConfig 的 patch undefined 删除与 sessionFile 回退。
import { describe, it, expect } from 'vitest';
import { parseScopeList, buildStartConfig, buildResumeConfig } from '../shared/scanConfig';

describe('parseScopeList: 授权范围输入解析', () => {
  it('换行 / 逗号 / 分号都能作为分隔符', () => {
    expect(parseScopeList('a.com\nb.com')).toEqual(['a.com', 'b.com']);
    expect(parseScopeList('a.com,b.com')).toEqual(['a.com', 'b.com']);
    expect(parseScopeList('a.com;b.com')).toEqual(['a.com', 'b.com']);
    expect(parseScopeList('a\nb,c;d')).toEqual(['a', 'b', 'c', 'd']);
  });

  it('连续分隔符与首尾留白不产生空条目（空条目会被后端当成匹配一切）', () => {
    expect(parseScopeList('a,,b\n\nc,')).toEqual(['a', 'b', 'c']);
    expect(parseScopeList('  ,  ,  ')).toEqual([]);
  });

  it('每项去首尾空白但保留内容里的空白语义', () => {
    expect(parseScopeList('  a.com  ,  b.com')).toEqual(['a.com', 'b.com']);
  });

  it('空 / 纯空白 / null / undefined → 空数组（留空 = 不启用范围限制）', () => {
    expect(parseScopeList('')).toEqual([]);
    expect(parseScopeList('   ')).toEqual([]);
    // @ts-expect-error 故意喂 undefined：签名是 raw: string，测的是容错分支
    expect(parseScopeList(undefined)).toEqual([]);
    // @ts-expect-error 故意喂 null（同上）
    expect(parseScopeList(null)).toEqual([]);
  });

  it('数字等非字符串输入经 String() 兜底（宽容转换，钉住行为防漂移）', () => {
    // 实现是 String(raw ?? '')：数字会变成一段普通文本而不是被丢弃。这不构成范围语义
    // （"123" 匹配不到任何主机），但行为必须被钉住——将来若改成「非字符串一律 []」，
    // 本断言会先炸，提醒改的人确认调用方没有依赖。
    // @ts-expect-error 故意喂数字 123：实现是 String(raw ?? '')
    expect(parseScopeList(123)).toEqual(['123']);
    // @ts-expect-error 故意喂 0（falsy 但非空，走的是同一条兜底）
    expect(parseScopeList(0)).toEqual(['0']);
  });

  it('CIDR 与 URL 前缀条目原样保留（不被分隔符合误切）', () => {
    expect(parseScopeList('10.0.0.0/8, https://example.com/app')).toEqual(['10.0.0.0/8', 'https://example.com/app']);
  });
});

describe('buildStartConfig: stringArray 归一化（scope / techniques）', () => {
  it('scope 传逗号串 → 归一化为数组（后端只认数组）', () => {
    // @ts-expect-error 故意传 string（声明是 string[]）：测的正是"面板里那种一行的写法"能否归一
    const out = buildStartConfig({ scope: 'a.com,b.com' });
    expect(out.scope).toEqual(['a.com', 'b.com']);
  });

  it('techniques 传字符串 → 同样归一化为数组', () => {
    // @ts-expect-error 故意传 string
    const out = buildStartConfig({ techniques: 'union,error' });
    expect(out.techniques).toEqual(['union', 'error']);
  });

  it('传数组 → 过滤空串与纯空白项', () => {
    // 这个入参是**合法类型**（string[]），不需要 cast —— 原先写成 `as never`
    // 会把"参数类型以后再变"这件事一起关掉。
    const out = buildStartConfig({ scope: ['a.com', '', '   '] });
    expect(out.scope).toEqual(['a.com']);
  });

  it('空串 → 空数组（关闭态，不污染请求体）', () => {
    // @ts-expect-error 故意传 ''
    const out = buildStartConfig({ scope: '' });
    expect(out.scope).toEqual([]);
  });

  it('类型非法的键被整体剔除，而不是带着错值发出去', () => {
    // level 声明为 number：'abc' 无法归一化 → 必须从请求体删除
    // @ts-expect-error 故意传 string
    const out = buildStartConfig({ level: 'abc' });
    expect('level' in out).toBe(false);
  });
});

describe('buildResumeConfig: 续跑配置的授权范围继承', () => {
  // 以下入参全部落在签名 `Partial<ScanConfig> | null` 内 —— 原先那 7 个 `as never`
  // 是把参数类型整个关掉：以后 buildResumeConfig 改了签名，这些用例会照样绿。
  it('显式 patch 为 undefined → 该键被删除（可主动清除范围）', () => {
    const out = buildResumeConfig({ scope: ['a.com'] }, { scope: undefined });
    expect('scope' in out).toBe(false);
  });

  it('patch 覆写 scope', () => {
    const out = buildResumeConfig({ scope: ['old.com'] }, { scope: ['new.com'] });
    expect(out.scope).toEqual(['new.com']);
  });

  it('开了断点续跑但未给会话文件名 → 回退默认会话名', () => {
    const out = buildResumeConfig({ sessionDefault: true });
    expect(out.sessionFile).toBe('sqli-session-latest.json');
  });

  it('已显式给会话文件名时不回退覆盖', () => {
    const out = buildResumeConfig({ sessionDefault: true, sessionFile: 'mine.json' });
    expect(out.sessionFile).toBe('mine.json');
  });

  it('saved 为 null/undefined 不抛错（返回 patch 本身）', () => {
    expect(buildResumeConfig(null, { scope: ['a.com'] }).scope).toEqual(['a.com']);
    expect(buildResumeConfig(undefined, { scope: ['b.com'] }).scope).toEqual(['b.com']);
  });
});
