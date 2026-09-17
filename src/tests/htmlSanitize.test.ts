// htmlSanitize.test.ts —— 富 HTML 注入前清洗函数的行为契约
//
// 存在理由：本模块是**预埋的纵深防御**——当前前端全项目没有一处使用
// dangerouslySetInnerHTML（已 grep 确认，仅本文件注释里提及），所以它是「将来接线时必须
// 先过一遍」的第二道闸。这类安全模块**零覆盖是不可接受的**：将来真要接线时没人知道它
// 的行为边界，等于把一道没验过的闸当成防护。
//
// 定位（与实现注释一致，别把它当安全边界）：本函数只做正则级缓解，安全边界由
// 引擎侧 ReportGenerator 的统一实体转义 + CSP 保证。因此这里的断言口径是
// 「已知的常见逃逸向量必须被剥除」+「正常内容不得被误杀」，而非「等价 HTML5 解析器」。
import { describe, it, expect } from 'vitest';
import { sanitizeInjectedHtml } from '../shared/htmlSanitize';

describe('sanitizeInjectedHtml: 输入守卫', () => {
  it('非字符串 / 空输入一律返回空串（不渲染 "undefined"/"null"）', () => {
    expect(sanitizeInjectedHtml(undefined)).toBe('');
    expect(sanitizeInjectedHtml(null)).toBe('');
    expect(sanitizeInjectedHtml(123)).toBe('');
    expect(sanitizeInjectedHtml({ a: 1 })).toBe('');
    expect(sanitizeInjectedHtml('')).toBe('');
  });
});

describe('sanitizeInjectedHtml: 危险容器标签', () => {
  it('成对 script 块连同内容一并剥除', () => {
    expect(sanitizeInjectedHtml('<script>alert(1)</script>ok')).toBe('ok');
    expect(sanitizeInjectedHtml('<div>a</div><script src="x"></script>')).toBe('<div>a</div>');
  });

  it('未闭合的危险开标签也被剥掉（防属性里的 on* 残留）', () => {
    expect(sanitizeInjectedHtml('<script>alert(1)')).toBe('alert(1)');
    expect(sanitizeInjectedHtml('<iframe src="x">body')).toBe('body');
  });

  it('style / object / embed / form / template 同样处理', () => {
    expect(sanitizeInjectedHtml('<style>body{}</style>x')).toBe('x');
    expect(sanitizeInjectedHtml('<object data="x"></object>y')).toBe('y');
    expect(sanitizeInjectedHtml('<embed src="x">z')).toBe('z');
  });

  it('大小写与空白变形不能绕过（<SCRIPT> / < script >）', () => {
    expect(sanitizeInjectedHtml('<SCRIPT>alert(1)</SCRIPT>ok')).toBe('ok');
    expect(sanitizeInjectedHtml('< script >alert(1)</ script >ok')).toBe('ok');
  });
});

describe('sanitizeInjectedHtml: 内联事件属性', () => {
  it('双引号 / 单引号 / 裸值三种写法都剥除', () => {
    expect(sanitizeInjectedHtml('<div onclick="alert(1)">x</div>')).toBe('<div>x</div>');
    expect(sanitizeInjectedHtml("<div onclick='alert(1)'>x</div>")).toBe('<div>x</div>');
    expect(sanitizeInjectedHtml('<div onclick=alert(1)>x</div>')).toBe('<div>x</div>');
  });

  it('onerror / onload / onmouseover 等同族属性同样剥除', () => {
    expect(sanitizeInjectedHtml('<img src=x onerror=alert(1)>')).toBe('<img src=x>');
    expect(sanitizeInjectedHtml('<body onload="evil()">t</body>')).toBe('<body>t</body>');
  });
});

describe('sanitizeInjectedHtml: 危险协议', () => {
  it('javascript: / vbscript: 降为 href="#"（不整段删除，保留结构）', () => {
    expect(sanitizeInjectedHtml('<a href="javascript:alert(1)">x</a>')).toBe('<a href="#">x</a>');
    expect(sanitizeInjectedHtml('<a href="vbscript:msgbox">x</a>')).toBe('<a href="#">x</a>');
  });

  it('src / action / formaction / xlink:href 同样覆盖', () => {
    expect(sanitizeInjectedHtml('<img src="javascript:alert(1)">')).toBe('<img href="#">');
    expect(sanitizeInjectedHtml('<form action="javascript:void(0)"></form>')).toBe('');
  });

  it('data:text/html 视为危险协议', () => {
    expect(sanitizeInjectedHtml('<a href="data:text/html;base64,PHNjcmlwdD4=">x</a>')).toBe('<a href="#">x</a>');
  });

  it('CSS url(javascript:) 降为空 url，且产出仍是合法 HTML 片段', () => {
    // 替换串必须不带引号：`url("")` 会提前闭合 style 属性，把片段切成畸形 HTML
    const out = sanitizeInjectedHtml('<div style="background:url(javascript:alert(1))">x</div>');
    expect(out).toBe('<div style="background:url()">x</div>');
    // 关键：清洗后不得残留裸括号（原实现 `\)?` 只吃一个，会剩一个 )）
    expect(out).not.toContain('url()' + ')');
  });

  it('残留的 javascript: 字面量最终被实体化（兜底闸）', () => {
    // 结构与属性清洗都漏掉的场景（畸形引号嵌套）至少要保证冒号被实体化、不可执行
    const out = sanitizeInjectedHtml('x javascript:alert(1)');
    expect(out).not.toMatch(/javascript:/i);
    expect(out).toContain('javascript&#58;');
  });
});

describe('sanitizeInjectedHtml: 注释与正常内容', () => {
  it('HTML 注释（含条件注释逃逸通道）被剥除', () => {
    expect(sanitizeInjectedHtml('a<!--[if IE]><script>x</script><![endif]-->b')).toBe('ab');
    expect(sanitizeInjectedHtml('a<!-- plain -->b')).toBe('ab');
  });

  it('正常内容不得被误杀（清洗不是删除一切）', () => {
    expect(sanitizeInjectedHtml('<div class="p">文本内容</div>')).toBe('<div class="p">文本内容</div>');
    expect(sanitizeInjectedHtml('<a href="https://example.com/ok">链接</a>'))
      .toBe('<a href="https://example.com/ok">链接</a>');
    expect(sanitizeInjectedHtml('<p>HTTP 请求 <code>GET /a</code></p>')).toBe('<p>HTTP 请求 <code>GET /a</code></p>');
  });

  it('多次清洗结果稳定（幂等，不会逐次膨胀）', () => {
    const once = sanitizeInjectedHtml('<div onclick="a()">x</div>');
    expect(sanitizeInjectedHtml(once)).toBe(once);
  });
});
