// 沙箱「端口亮着 ≠ 本沙箱在跑」守卫（TODO T 条 / 2026-10-12）
//
// 背景：`e2e/udf-lab/mysql_sandbox.py` 的 `do_start()` 原先只判 `_port_open(3308)` ⇒
// 端口被**任何**进程占用（上一套件残留的 mysqld、正在关闭中的实例、甚至别的程序）
// 都会立刻返回「已在运行」，靶场于是拿一个**身份不明的实例**跑完全程 ——
// 这正是 TODO T 条「udf-lab 约一半概率跑挂」的机理。
//
// 为什么要有这道守卫：那份 .py **不在 node 测试能直接调用的范围里**（node 起 python
// 子进程在本机会话内 EBUSY，CI 上也不打算为它单开 job）⇒ 只靠 `mysql_sandbox.py --selftest`
// 的话，它极易变成「写了但没人跑」的脚本（本仓 D24 治理过的老病）。
// 这里用**源码级断言**把判据钉死，随 `test-server` job 每次都跑；selftest 则留给
// 人/CI 手工复验（见该文件的 `--selftest` 说明）。两层互为补充，不是替代。
//
// ⚠️ 判据的文本源先剥整行 `#` 注释 —— 本仓纪律（D21 教训：注释里的反面示例被当成真分支）。

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const SB = path.join(REPO, 'e2e', 'udf-lab', 'mysql_sandbox.py');

/** 剥掉整行注释（`^\s*#`）后再匹配，避免把说明文字当成实现。 */
function codeOnly(src) {
  return src.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
}

// [CI-FIX 2026-10-14] CRLF 归一：windows runner 检出的 mysql_sandbox.py 是 CRLF，
// 而下面截函数体用 `/def do_start\([\s\S]*?\n\ndef /` —— 边界写的是**连续两个 `\n`**，
// CRLF 下是 `\r\n\r\n`（中间夹着 `\r`）⇒ 永远匹配不到，三条断言全报「截不到函数体」
// （CI windows 实测 3 红）。归一后两平台同判。
const src = readFileSync(SB, 'utf8').replace(/\r\n/g, '\n');
const code = codeOnly(src);

test('分母守卫：读到的确实是 mysql_sandbox.py 且内容非空', () => {
  assert.ok(code.length > 8000, `源码只有 ${code.length} 字符 —— 路径或读取方式变了，下面所有断言都会失去意义`);
  assert.match(code, /def do_start\(/, '读到的文件里没有 do_start —— 路径写错了');
});

test('★ do_start 不得只凭「端口在监听」就认定沙箱已就绪', () => {
  // 反例（被本守卫禁止的形状）：
  //     if _port_open(SANDBOX_PORT):
  //         print("已在运行")
  //         return 0
  // 只看门牌号亮没亮，不问住的是谁 ⇒ 连到残留实例/主库照样跑完全程。
  const m = code.match(/def do_start\([\s\S]*?\n\ndef /);
  assert.ok(m, '截不到 do_start 函数体');
  const body = m[0];
  assert.match(body, /_port_open\(SANDBOX_PORT\)/, 'do_start 应当仍以端口探测作为入口');
  assert.match(
    body,
    /_sandbox_alive\(\)/,
    'do_start 必须调用身份探针：端口亮着只说明"有人在听"，说明不了"是谁在听"',
  );
  // 两处都要验：① 启动前发现端口已被占用（复用分支）② 启动后确认真的能服务
  const calls = body.match(/_sandbox_alive\(\)/g) || [];
  assert.ok(
    calls.length >= 2,
    `身份探针只调用了 ${calls.length} 次 —— 复用分支与就绪判定各需要一次（少一次就会留一个"端口亮了就跑"的口子）`,
  );
});

test('★ 身份探针必须以 datadir 判身份，而不是只判连接成功', () => {
  const m = code.match(/def _sandbox_alive\([\s\S]*?\n\ndef /);
  assert.ok(m, '找不到 _sandbox_alive 定义');
  const body = m[0];
  assert.match(body, /@@datadir/, '判据要问"你是谁"——取 @@datadir 才能区分沙箱与主库');
  assert.match(
    body,
    /\.mysql-sandbox/,
    '必须校验 datadir 路径里含沙箱目录名（否则连到主库 D:\\mysql\\data 也会被当成"已在运行"）',
  );
  assert.match(body, /rc != 0/, '连不上（半死实例）必须判失败，不能当"已在运行"');
});

test('do_start 的拒绝复用路径必须返回非零（否则 launch() 不会拦住）', () => {
  // SandboxInstance.__enter__ 里 `if rc != 0: raise` —— 返回 0 等于放行。
  const m = code.match(/def do_start\([\s\S]*?\n\ndef /);
  assert.match(m[0], /return 3/, '身份不符时要返回一个明确的非零码（3），让调用方直接失败而不是继续跑');
});

test('--selftest 入口必须还在（它是本机不起进程就能复验这套判据的唯一入口）', () => {
  assert.match(code, /--selftest/, 'mysql_sandbox.py 少了 --selftest 入口');
  assert.match(code, /def do_selftest\(/, '没有 do_selftest 实现');
  assert.match(
    code,
    /期望 3（拒绝）/,
    'selftest 必须覆盖"占用者是主库 / 半死实例"两种拒绝场景（缺了就抓不出退化）',
  );
});
