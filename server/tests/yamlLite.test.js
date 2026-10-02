// ============================================================================
// yamlLite.test.js —— 零依赖 YAML 子集解析器
//
// 本模块只为 OpenAPI/Swagger 服务，所以判据就两条，缺一不可：
//   ① **能吃的必须吃对**：嵌套 map、序列、`- key: value` 的序列项、行内流式集合、
//      引号标量、数字/布尔/null、URL 里的 `#`（不是注释）。
//      吃错 = 展开出**错的** HTTP 请求（少参数、少路径）⇒ 静默少测目标。
//   ② **吃不下的必须整体拒绝并给原因**：锚点/别名/标签/块标量/合并键/TAB 缩进/多文档。
//      半解的 YAML 会产出结构缺字段的伪文档 —— 那比明确说"解析不了"危险得多。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseYamlLite } from '../src/core/yamlLite.js';

const ok = (t) => {
  const r = parseYamlLite(t);
  assert.equal(r.ok, true, `应解析成功，实得失败：${r.reason}`);
  return r.value;
};

test('yamlLite: 扁平 map 与标量类型', () => {
  const v = ok('openapi: 3.0.0\nport: 8080\nratio: 0.5\ndebug: true\nnote: null\nname: lab\n');
  assert.equal(v.openapi, '3.0.0'); // 形似版本号但不是数字 ⇒ 保持字符串
  assert.equal(v.port, 8080);
  assert.equal(v.ratio, 0.5);
  assert.equal(v.debug, true);
  assert.equal(v.note, null);
  assert.equal(v.name, 'lab');
});

test('yamlLite: 嵌套 map（缩进层级）', () => {
  const v = ok('info:\n  title: t\n  contact:\n    email: a@b.c\nservers:\n  - url: http://x\n');
  assert.deepEqual(v.info, { title: 't', contact: { email: 'a@b.c' } });
  assert.deepEqual(v.servers, [{ url: 'http://x' }]);
});

test('yamlLite: 序列项是 map（`- name: id` + 后续同项字段）', () => {
  // 这是 OpenAPI parameters / servers 最常用的形态，也是本解析器最容易写错的地方：
  // `- name: id` 的"逻辑缩进"在 `-` 之后两列，后续 `in: query` 属于**同一项**而不是下一项。
  const v = ok([
    'parameters:',
    '  - name: id',
    '    in: query',
    '    required: true',
    '    example: 1',
    '  - name: q',
    '    in: query',
    '    example: abc',
    '',
  ].join('\n'));
  assert.deepEqual(v.parameters, [
    { name: 'id', in: 'query', required: true, example: 1 },
    { name: 'q', in: 'query', example: 'abc' },
  ]);
});

test('yamlLite: 行内流式集合 [a, b] / {a: b}', () => {
  const v = ok('required: [id, q]\nmeta: {a: 1, b: two}\nempty: []\n');
  assert.deepEqual(v.required, ['id', 'q']);
  assert.deepEqual(v.meta, { a: 1, b: 'two' });
  assert.deepEqual(v.empty, []);
});

test('yamlLite: 引号标量与行尾注释（URL 里的 # 不是注释）', () => {
  const v = ok([
    'url: http://t.local/api#frag   # 这是真注释',
    "title: 'a: b'",
    'desc: "say \\"hi\\""',
    '',
  ].join('\n'));
  assert.equal(v.url, 'http://t.local/api#frag', 'URL fragment 不能被当注释剥掉');
  assert.equal(v.title, 'a: b', '引号内的冒号不是键分隔');
  assert.equal(v.desc, 'say "hi"');
});

test('yamlLite: 键无值（值为 null）', () => {
  const v = ok('a:\nb: 1\n');
  assert.equal(v.a, null);
  assert.equal(v.b, 1);
});

// —— ② 拒绝并给原因（绝不半解）——
const rejects = [
  ['锚点', 'a: &x\n  b: 1\n'],
  ['别名', 'a: *x\n'],
  ['标签', "a: !!str 'x'\n"],
  ['块标量', 'a: |\n  line1\n'],
  ['折叠块标量', 'a: >-\n  line1\n'],
  ['合并键', 'a:\n  <<: *base\n'],
  ['TAB 缩进', 'a:\n\tb: 1\n'],
  ['复杂键', '? a\n: b\n'],
  ['多文档', 'a: 1\n---\nb: 2\n'],
];

for (const [name, text] of rejects) {
  test(`yamlLite: ${name} 必须整体拒绝（不能半解）`, () => {
    const r = parseYamlLite(text);
    assert.equal(r.ok, false, `${name} 应被拒绝，却解析成功了`);
    assert.ok(r.reason && r.reason.length > 0, '拒绝时必须给出原因（用户要靠它决定怎么改）');
  });
}

test('yamlLite: 空内容 / 只有注释 ⇒ 拒绝且不抛', () => {
  assert.equal(parseYamlLite('').ok, false);
  assert.equal(parseYamlLite('# 只有注释\n').ok, false);
});

test('yamlLite: 文件开头的 --- 是合法文档标记（不该被当成多文档）', () => {
  assert.equal(parseYamlLite('---\nopenapi: 3.0.0\n').ok, true);
});

// 真实形态：一份够用的 OpenAPI YAML（servers/paths/parameters/requestBody）
test('yamlLite: 真实 OpenAPI YAML 片段能还原出同一结构', () => {
  const v = ok([
    'openapi: 3.0.0',
    'servers:',
    '  - url: http://127.0.0.1:8080',
    'paths:',
    '  /user/{id}:',
    '    get:',
    '      parameters:',
    '        - name: id',
    '          in: path',
    '          required: true',
    '          schema:',
    '            type: integer',
    '          example: 7',
    '    post:',
    '      requestBody:',
    '        content:',
    '          application/json:',
    '            example: {name: alice}',
    '',
  ].join('\n'));
  assert.equal(v.openapi, '3.0.0');
  assert.equal(v.servers[0].url, 'http://127.0.0.1:8080');
  const get = v.paths['/user/{id}'].get;
  assert.equal(get.parameters[0].in, 'path');
  assert.equal(get.parameters[0].example, 7);
  assert.deepEqual(v.paths['/user/{id}'].post.requestBody.content['application/json'].example, { name: 'alice' });
});
