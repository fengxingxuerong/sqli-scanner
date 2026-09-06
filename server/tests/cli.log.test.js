// CLI 日志批量模式单测（对标 sqlmap -l）
// 覆盖：
//   1) parseArgs：-l/--log-file 与 --check-tor 参数解析
//   2) parseLogFile：Burp XML 导出解析
//   3) parseLogFile：纯文本多请求日志切分解析
//   4) parseLogFile：无法识别内容返回空数组
//   5) resolveDbms/dialectToDbms：边缘库方言别名归一化（OceanBase/Cubrid/GBase→MySQL，
//      CockroachDB/Kingbase/Vertica→PostgreSQL）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs, parseLogFile, buildConfig, resolveTamperPlugins } from '../bin/cli.js';
import { resolveDbms, dialectToDbms } from '../src/engine/DialectSqlBuilder.js';

function withTmpFile(name, content) {
  const dir = mkdtempSync(join(tmpdir(), 'sqli-cli-log-'));
  const file = join(dir, name);
  writeFileSync(file, content, 'utf-8');
  return { dir, file };
}

// ─────────────── 1) parseArgs ───────────────
test('parseArgs: -l/--log-file 与 --check-tor 解析', () => {
  const a = parseArgs(['-l', 'access.log', '--check-tor', '--tor']);
  assert.equal(a.logFile, 'access.log');
  assert.equal(a.checkTor, true);
  assert.equal(a.tor, true);
});

// ─────────────── 2) Burp XML 导出 ───────────────
test('parseLogFile: Burp XML 提取 url/method（跳过非 http 与不支持方法）', () => {
  const xml = `<?xml version="1.0"?>
<items>
  <item>
    <method><![CDATA[GET]]></method>
    <url><![CDATA[https://example.com/item.php?id=1]]></url>
  </item>
  <item>
    <method><![CDATA[POST]]></method>
    <url><![CDATA[http://t2/login.php]]></url>
  </item>
  <item>
    <method><![CDATA[CONNECT]]></method>
    <url><![CDATA[https://t3:443/]]></url>
  </item>
  <item>
    <method><![CDATA[GET]]></method>
    <url><![CDATA[ftp://nope/file]]></url>
  </item>
</items>`;
  const { dir, file } = withTmpFile('burp.xml', xml);
  try {
    const out = parseLogFile(file);
    assert.equal(out.length, 2, '仅保留 GET/POST 且 http(s) 的请求');
    assert.equal(out[0].url, 'https://example.com/item.php?id=1');
    assert.equal(out[0].method, 'GET');
    assert.equal(out[1].url, 'http://t2/login.php');
    assert.equal(out[1].method, 'POST');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ─────────────── 3) 纯文本多请求日志 ───────────────
test('parseLogFile: 纯文本多请求按请求行切分', () => {
  const log = `2026-09-01 12:00:00 GET https://a.com/x?id=1 HTTP/1.1
Host: a.com
Cookie: sid=abc

2026-09-01 12:00:01 POST https://b.com/login HTTP/1.1
Host: b.com
Content-Type: application/x-www-form-urlencoded

user=admin&pass=1`;
  const { dir, file } = withTmpFile('access.log', log);
  try {
    const out = parseLogFile(file);
    assert.equal(out.length, 2, '切分为 2 个请求');
    assert.equal(out[0].url, 'https://a.com/x?id=1');
    assert.equal(out[0].method, 'GET');
    assert.equal(out[1].url, 'https://b.com/login');
    assert.equal(out[1].method, 'POST');
    assert.match(String(out[1].body || ''), /user=admin/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('parseLogFile: 无法识别内容返回空数组；文件不存在返回空数组', () => {
  const { dir, file } = withTmpFile('garbage.log', 'plain text no http requests');
  try {
    assert.equal(parseLogFile(file).length, 0);
    assert.equal(parseLogFile(join(dir, 'nope.log')).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ─────────────── 4) 边缘库方言别名归一化 ───────────────
test('resolveDbms: 边缘库归一化到母库（OceanBase/Cubrid/GBase→MySQL，CockroachDB/Kingbase→PG）', () => {
  assert.equal(resolveDbms('OceanBase'), 'MySQL');
  assert.equal(resolveDbms('cubrid'), 'MySQL');
  assert.equal(resolveDbms('GBase 8a'), 'MySQL');
  assert.equal(resolveDbms('MaxDB'), 'MySQL');
  assert.equal(resolveDbms('CockroachDB'), 'PostgreSQL');
  assert.equal(resolveDbms('KingbaseES'), 'PostgreSQL');
  assert.equal(resolveDbms('Vertica'), 'PostgreSQL');
  // 既有归一化不回归
  assert.equal(resolveDbms('MariaDB'), 'MySQL');
  assert.equal(resolveDbms('DM8'), 'Oracle');
  assert.equal(resolveDbms('PostgreSQL'), 'PostgreSQL');
});

test('dialectToDbms: 边缘库方言映射到标准库名', () => {
  assert.equal(dialectToDbms('oceanbase'), 'MySQL');
  assert.equal(dialectToDbms('cockroachdb'), 'PostgreSQL');
  assert.equal(dialectToDbms('kingbase'), 'PostgreSQL');
  assert.equal(dialectToDbms('vertica'), 'PostgreSQL');
  assert.equal(dialectToDbms('mysql'), 'MySQL');
  assert.equal(dialectToDbms('unknown-dialect'), null);
});

// ─────────────── 5) 攻击操作参数（对标 sqlmap --os-cmd/--sql-shell/--file-*） ───────────────
test('parseArgs: 攻击操作与 --dbms/--second-order/--authorized 解析', () => {
  const a = parseArgs([
    '-u', 'http://x/?id=1',
    '--os-cmd', 'id',
    '--sql-shell', 'SELECT 1',
    '--file-read', '/etc/passwd',
    '--file-write', 'hello', '--file-dest', '/tmp/h.txt',
    '--dbms', 'MySQL',
    '--second-order', 'http://x/profile',
    '--authorized',
  ]);
  assert.equal(a.osCmd, 'id');
  assert.equal(a.sqlShell, 'SELECT 1');
  assert.equal(a.fileRead, '/etc/passwd');
  assert.equal(a.fileWrite, 'hello');
  assert.equal(a.fileDest, '/tmp/h.txt');
  assert.equal(a.dbms, 'MySQL');
  assert.equal(a.secondOrderUrl, 'http://x/profile');
  assert.equal(a.authorized, true);
});

test('buildConfig: --dbms 透传 + --second-order 构造二阶配置', () => {
  const a = parseArgs(['-u', 'http://x/?id=1', '--dbms', 'PostgreSQL', '--second-order', 'http://x/trigger.php']);
  const cfg = buildConfig(a);
  assert.equal(cfg.dbms, 'PostgreSQL');
  assert.equal(cfg.secondOrder.enabled, true);
  assert.deepEqual(cfg.secondOrder.triggerUrls, ['http://x/trigger.php']);
});

// ─────────────── 6) 自定义 tamper 文件（对标 sqlmap --tamper=path/to/script） ───────────────
test('resolveTamperPlugins: 自定义 .js 插件动态加载注册；内置名原样返回', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sqli-tamper-'));
  try {
    // 自定义插件：把 payload 中的空格替换为注释块（space2comment 语义）
    const plugin = `export default {
      name: 'custom_space2comment',
      description: 'test plugin: space to comment',
      transform(payload, ctx) {
        return String(payload ?? '').replace(/ /g, '/**/');
      },
    };`;
    const file = join(dir, 'custom.js');
    writeFileSync(file, plugin, 'utf-8');

    const names = await resolveTamperPlugins(file);
    assert.deepEqual(names, ['custom_space2comment']);

    // 内置名原样返回（不加载文件）
    const mixed = await resolveTamperPlugins(`randomcase,${file}`);
    assert.deepEqual(mixed, ['randomcase', 'custom_space2comment']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveTamperPlugins: 不存在的文件 / 缺 transform 的插件被忽略', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sqli-tamper-bad-'));
  try {
    const bad = join(dir, 'bad.js');
    writeFileSync(bad, 'export default { name: "noop" };', 'utf-8'); // 缺 transform
    const names = await resolveTamperPlugins(`${bad},missing-file.js`);
    assert.deepEqual(names, [], '非法插件与缺失文件均被忽略');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
