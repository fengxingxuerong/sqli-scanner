// DBFingerprinter 版本化条件注释探测（sqlmap 风格 /*!50000 ... */）单元测试
// 覆盖：① 明文 UNION 被 WAF 剥离、条件注释放行 → 兜底识别 MySQL；
//       ② 条件注释不被执行（SQLite 类）→ 不误报。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DBFingerprinter } from '../src/engine/DBFingerprinter.js';

// 模拟 MySQL 靶机但带 WAF：明文 "UNION SELECT ... version()" 被剥离（无标记），
// 条件注释 /*!50000 UNION SELECT ...*/ 被放行（回显版本标记）；标记探针 UNION 正常回显。
function makeMysqlWafMock() {
  const baseline = '<html>user page normal content here</html>';
  return {
    async request(opts) {
      // 注入值经 URL 编码（!→%21、空格→+、/→%2F 等），先解码再匹配字面量
      const url = decodeURIComponent((opts.url || '').replace(/\+/g, ' '));
      // ORDER BY 列数二分：≤3 正常，>3 报错（500 短）
      const ob = url.match(/ORDER BY (\d+)/);
      if (ob) {
        const n = Number(ob[1]);
        if (n > 3) return { status: 500, data: 'ERR' };
        return { status: 200, data: baseline };
      }
      // 条件注释 UNION（WAF 放行）→ 回显版本标记
      if (url.includes('/*!50000 UNION SELECT')) {
        return { status: 200, data: '<html>result __S__5.7.40__E__ end</html>' };
      }
      // 明文 UNION 含 version()（被 WAF 剥离）→ 无标记
      if (url.includes('UNION SELECT') && url.includes('version()')) {
        return { status: 200, data: baseline };
      }
      // 明文 UNION 标记探测（discoverEchoColumns，无 version()）→ 回显 SQLISCANNER1
      if (url.includes('UNION SELECT') && url.includes('SQLISCANNER1')) {
        return { status: 200, data: '<html>id=1 name=SQLISCANNER1 email=x</html>' };
      }
      return { status: 200, data: baseline };
    },
  };
}

// 模拟 SQLite 类靶机：条件注释不被执行（当普通注释）→ 不回显标记
function makeSqliteMock() {
  const baseline = '<html>row username here</html>';
  return {
    async request(opts) {
      const url = decodeURIComponent((opts.url || '').replace(/\+/g, ' '));
      const ob = url.match(/ORDER BY (\d+)/);
      if (ob) {
        const n = Number(ob[1]);
        if (n > 3) return { status: 500, data: 'ERR' };
        return { status: 200, data: baseline };
      }
      // 任意 UNION（含条件注释）都只回显普通内容，不回显 __S__ 标记
      if (url.includes('UNION SELECT')) {
        return { status: 200, data: '<html>id=1 name=alice email=x</html>' };
      }
      return { status: 200, data: baseline };
    },
  };
}

function mkCtx(httpClient) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?id=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'id', originalValue: '1' },
    config: { maxColumnsGuess: 10 },
  };
}

test('明文 UNION 被 WAF 剥离、条件注释放行 → 兜底识别 MySQL', async () => {
  const fp = new DBFingerprinter();
  const r = await fp.fingerprint(mkCtx(makeMysqlWafMock()));
  assert.equal(r.dbms, 'MySQL', `应兜底识别为 MySQL，实际 ${r.dbms}`);
});

test('probeVersionComment 直接调用：条件注释被放行返回 MySQL', async () => {
  const fp = new DBFingerprinter();
  const r = await fp.probeVersionComment(mkCtx(makeMysqlWafMock()), 3, [1]);
  assert.equal(r, 'MySQL');
});

test('条件注释不被执行（SQLite 类）→ probeVersionComment 返回 null，不误报', async () => {
  const fp = new DBFingerprinter();
  const r = await fp.probeVersionComment(mkCtx(makeSqliteMock()), 3, [1]);
  assert.equal(r, null);
});

test('条件注释不被执行时完整 fingerprint 不清真误报为 MySQL', async () => {
  const fp = new DBFingerprinter();
  const r = await fp.fingerprint(mkCtx(makeSqliteMock()));
  assert.notEqual(r.dbms, 'MySQL', 'SQLite 类靶机不应被误判为 MySQL');
});
