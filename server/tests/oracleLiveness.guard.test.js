// ============================================================================
// extractor 布尔预言机的「活性」守卫（2026-10-05 新增）
//
// ── 要防的是什么 ─────────────────────────────────────────────────────────────
// server/tests 里大量用「手写布尔预言机」模拟目标数据库：mock 的 httpClient 解析
// 引擎发出的 payload，按 payload 里编码的判据返回 'OK' / ''，引擎据此二分收敛。
// 这类预言机强大，但**依赖正则反解 payload**，于是和生产的 SQL 构造器**同源漂移**：
//
//   · 构造器把 LENGTH( 改名为别的 → 长度探测正则 `/(?:LENGTH|LEN)\(/` 静默失配；
//   · 方言分支改了括号层数（见 blindFns.js 里 PostgreSQL 的 FROM/FOR 写法）→ 同样失配。
//
// 失配后的行为链是：正则不中 → 落到 `return { data: '', status: 200 }`
// → 引擎认为「条件恒假」 → 二分立即收敛到 0 长度 → 返回 '' 或 null。
//
// **最危险的地方**：那些断言 `out === ''` 或只数请求条数的用例此时**照样通过** ——
// 绿灯本身就是 bug。这与本仓登记过的「空转门禁」（CI job 指向不存在的文件 +
// continue-on-error）是同一族：结论与真值分处两地。
//
// ── 判据为什么不用「照抄一份正则」────────────────────────────────────────────
// 本文件**不用**自己维护一份正则去猜构造器长什么样，而是反过来：
//   直接 import 生产侧的真实构造器（extraction/blindFns.js 的 LEN_FN / SUB_FN），
//   用它生成**真实的 payload 形状**，再喂给 extractor.test.js 里那份预言机正则。
// 这样构造器怎么改，这里都自动跟随；构造器改到预言机认不出，本文件立即红。
//
// 这是本文件与「复制正则」写法的本质区别，也是它能长期有效的原因。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LEN_FN, SUB_FN, ASCII_FN } from '../src/engine/extraction/blindFns.js';
import { resolveDbms } from '../src/engine/DialectSqlBuilder.js';

// ── 与 extractor.test.js 中那份预言机**逐字同款**的反解正则 ───────────────────
// 刻意复制而非 import：那份在测试文件内部、不导出。
// 复制本身就是有意的——本文件测的正是「那份正则还认不认得真实构造」，
// 若改成 import 生产侧判据，就变成自证（用同一份东西证明自己）。
//
// ⚠️ 两端的词边界 `(?<![A-Za-z0-9_])…(?![A-Za-z0-9_])` 是**本文件实测补上的**，
//   2026-10-05。两次踩坑的记录（都留在这里，免得下个人再犯）：
//     ① 首版写 `/LEN/i`，`OCTET_LENGTH` 的**尾部** LEN 被匹配 —— 前向边界缺失；
//     ② 只补 `(?![A-Za-z0-9_])`（尾部）仍不够 —— 因为 `OCTET_` 的下划线
//        本身已是非单词字符，`(?![A-Za-z0-9_])` 在它后面照样成立。
//   ⇒ 必须**前后都断**：函数名前不能紧跟字母/数字/下划线（否则 OCTET_LENGTH、
//     MY_LENGTH、XLEN 全被误命中），后同理（否则 LENGTHY 被误命中）。
//   过宽与过窄同样危险：过宽会让活性守卫失明（把"失配"伪装成"命中"）。
//
//   注：extractor.test.js 那份预言机此刻**只补了尾部边界**，前边界未补 ——
//   即它对 `OCTET_LENGTH` 仍会误判为命中。本文件活性-1/2 因此**不能**当作
//   那份正则的正确性证明，只能当作"生产构造器当前形态的快照 + 漂移告警"。
//   完整收口需要同步补前边界（独立一处），本文件负责盯住它不被悄悄改坏。
const LEN_PROBE = /(?<![A-Za-z0-9_])(?:LENGTH|LEN)(?![A-Za-z0-9_])\(\(.*?\)+\s*>\s*(\d+)/i;
const CHAR_PROBE = /(?<![A-Za-z0-9_])SUBSTR(?:ING)?(?![A-Za-z0-9_])\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/i;

// ── 那些真会用该预言机的方言（对应 extractor.test.js 的 MySQL 场景）───────────
// ⚠️ 故意**不**把 18 个方言全列进来：预言机只为 MySQL 构造的形状写死了正则，
//   PostgreSQL 的 `FROM i FOR 1` 等变体它本就认不出（那是 mock 的能力边界，
//   不是缺陷）。这里要钉的是「MySQL 这条主路径不许悄悄失配」。
const COVERED = ['MySQL'];

/** 用生产构造器生成一条真实的长度探测 payload（去括号，供正则反解） */
function realLenProbe(dbms) {
  const lenExpr = LEN_FN[dbms]('version()');
  return `1 AND ${lenExpr}>3`;
}

/** 用生产构造器生成一条真实的字符探测 payload */
function realCharProbe(dbms) {
  const subExpr = SUB_FN[dbms]('version()', '1');
  return `1 AND ${ASCII_FN[dbms](subExpr)}>48`;
}

test('活性-1) 长度探测：预言机必须认得生产构造器当前发出的形状', () => {
  for (const dbms of COVERED) {
    const p = realLenProbe(dbms);
    assert.match(p, LEN_PROBE,
      `长度探测失配（${dbms}）—— 真实构造为：${p}\n` +
      '若这是有意的方言改写，请同步更新 extractor.test.js 的预言机正则；' +
      '若不是，则该用例正在静默空转（绿灯即 bug）。');
  }
});

test('活性-2) 字符探测：预言机必须认得生产构造器当前发出的形状', () => {
  for (const dbms of COVERED) {
    const p = realCharProbe(dbms);
    assert.match(p, CHAR_PROBE,
      `字符探测失配（${dbms}）—— 真实构造为：${p}\n` +
      '同样：要么同步更新预言机，要么承认这条用例已不再验证任何东西。');
  }
});

test('活性-3) 覆盖方言逐一核对（不得用 some() 稀释）', () => {
  // ⚠️ 这里**必须逐方言断言**，不能用 `Object.values(...).some(...)`：
  //   用 some() 时，只要 18 个方言里还有任意一个含旧函数名，整条就恒真 ——
  //   而漏掉的正是最关键的那一个。实测记录（本文件 2026-10-05 首版即栽在这里）：
  //   把 MySQL 的 LENGTH 改成 OCTET_LENGTH 后，活性-1/2 因 COVERED 只有 MySQL 而**正确变红**，
  //   但活性-3 用 some() 判「全表里还有没有 LENGTH」——其余方言照样有 ⇒ **它假绿**。
  //   铁律：判据若覆盖的是一个集合，就必须逐个断言；只有真正断言全表时才用 some/every。
  for (const dbms of COVERED) {
    assert.match(LEN_FN[dbms]('x'), /\b(?:LENGTH|LEN)\b/i,
      `${dbms} 的 LEN_FN 不再是长度类函数 —— 预言机需整体重写`);
    assert.match(SUB_FN[dbms]('x', '1'), /SUBSTR(?:ING)?\s*\(/i,
      `${dbms} 的 SUB_FN 不再是取子串函数 —— 预言机需整体重写`);
  }
});

test('活性-3b) 全表普查：函数名形态分布（供改族时一眼看清影响面）', () => {
  // 这条**不**判定对错，只登记现状：若将来整体改族，这条会提示有多少方言受影响。
  // 它用 every/统计而非 some，因此不会像首版那样掩盖局部漂移。
  const lenNames = new Set(
    Object.entries(LEN_FN).map(([dbms, fn]) => {
      const m = fn('x').match(/^(\w+)\(/);
      return `${dbms}=${m ? m[1] : '?'}`;
    })
  );
  assert.ok(lenNames.size > 0, 'LEN_FN 不得为空表');
  // 不硬编码具体分布（那会随正常演进而红），只保证可被观察：
  assert.ok(lenNames.size <= Object.keys(LEN_FN).length);
});

test('活性-4) 噪声不得被误判为探针（正则过宽同样是无声失效）', () => {
  // 反向自证：判据不能"什么都匹配"。恒真的守卫等于没有守卫。
  const garbage = ['1 AND 1=1', '1', '', 'SELECT * FROM t', '1 AND foo(bar)>0'];
  const hits = garbage.filter((p) => LEN_PROBE.test(p) || CHAR_PROBE.test(p));
  assert.equal(hits.length, 0, `噪声被误判为探针：${JSON.stringify(hits)}`);
});

test('活性-5) 失配时的兜底是「恒假」—— 这正是必须靠活性断言才能识别的形态', async () => {
  // 把话说透：只断言「结果是空」的测试**分不清**下面两种情况 ——
  //   (a) 引擎正确地判定"长度探测返回 0"；
  //   (b) 预言机正则失配、什么都没解析出来。
  // 两者的返回值**完全相同**。因此活性断言（活性-1/2）不是冗余，是唯一的区分手段。
  //
  // 本条把 (b) 的形态显式造出来并断言其存在，以钉住这个事实本身。
  function deadOracle() {
    return {
      async request() {
        return { data: '', status: 200 }; // 正则失配后的兜底分支
      },
    };
  }
  const oracle = deadOracle();
  const res = await oracle.request({ url: 'http://x/?q=1' });
  assert.deepEqual(res, { data: '', status: 200 },
    '失配预言机的兜底返回空 —— 与「长度探测为 0」同形，故只能靠活性断言区分');
});

test('活性-6) resolveDbms 能把测试用的方言名归一（本文件自身的前置依赖）', () => {
  // 防止将来某个改动让 resolveDbms 对 MySQL 返回 null，从而让上面几条
  // 因为「取不到函数」而**假通过**（fn 为 undefined → 拼出 'undefined' → 正则不中 →
  // assert.match 本该红，但若有人把断言写松了就会静默）。
  for (const dbms of COVERED) {
    const norm = resolveDbms(dbms);
    assert.ok(norm && LEN_FN[norm] && SUB_FN[norm] && ASCII_FN[norm],
      `方言 ${dbms} 归一为 ${norm}，但 blindFns 里缺少对应函数`);
  }
});