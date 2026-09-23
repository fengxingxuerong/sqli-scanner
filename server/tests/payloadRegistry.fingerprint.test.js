// ============================================================================
// payloadRegistry.fingerprint.test.js —— 数据内容指纹（防「数据被静默改坏」）
//
// 为什么必须有（2026-09-23，E5 第二步切换加载源时实测发现）：
//   数据从 JS 内联搬到 `payloads/registry.json` 之后，风险形态变了 ——
//   以前「改坏」只会发生在改代码时，review 看得见；现在数据是外部文件，
//   一次手抖/一次脚本转义错误就能让某条模板静默变样。而**现有测试对此完全不敏感**：
//   实测把 `mysql-bool-sq-1` 的模板从 `{ORIG} AND 1=1` 改成 `...1=9`，
//   `payloadRegistry.test.js` + `registryFilter.test.js` 34 条**全绿**（它们断言的是
//   条数/筛选 id/level/risk，没人断言模板正文）。这类"改了却没人知道"正是本项目
//   反复出现的失败形态，故此处用内容指纹钉住。
//
// 判据三层：
//   ① 条数     —— 少一条/多一条都红；
//   ② id 序列   —— 顺序变化也红（顺序 = 投放优先级，不是可排序字段）；
//   ③ 内容指纹  —— 任一字段任一字符变化即红。
//
// 指纹口径：**排除 note**。note 是从 JS 行内注释迁移来的知识字段，引擎不消费它，
// 改注记不该要求改指纹（下面有一条测试专门钉这个解耦）。
//
// 指纹变了怎么办（数据改动是正常维护动作，不是错误）：
//   1) `git diff server/src/engine/payloads/registry.json` —— per-line 格式，能直接看到改了哪条；
//   2) 确认改动符合意图；
//   3) 把本文件里的 EXPECTED_* 换成测试报错里显示的 actual 值（assert 会把 actual 打出来）。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { PAYLOAD_REGISTRY } from '../src/engine/payloadRegistry.js';

const EXPECTED_COUNT = 681;
const EXPECTED_DATA_SHA = 'af113d87f60450c98315a77b3524b041311959b6e41f229f168e1981a9cd9379';
const EXPECTED_ID_SHA = '20106156250fa04a6c2f5b107b6c7d45ebd1ac42bbb4f675fb831e18c6dc60fb';

/** 去掉 note 后的条目（note 是知识字段，不进行为指纹） */
const strip = (e) => {
  const { note, ...rest } = e;
  return rest;
};
const sha = (v) => createHash('sha256').update(JSON.stringify(v)).digest('hex');
const dataOf = (list) => list.map(strip);

test('自证：指纹函数对已知输入稳定，且对单字符改动敏感（否则下面的相等是空转）', () => {
  assert.equal(sha([1, 2, 3]), sha([1, 2, 3]));
  assert.notEqual(sha([1, 2, 3]), sha([1, 2, 4]));
  assert.notEqual(sha(['a']), sha(['A']));
  // strip 必须真的剥掉 note（而不是把它留在指纹里）
  assert.deepEqual(strip({ id: 'x', note: 'y' }), { id: 'x' });
});

test('① 条数：注册表条目数', () => {
  assert.equal(
    PAYLOAD_REGISTRY.length,
    EXPECTED_COUNT,
    `条数变了（现在 ${PAYLOAD_REGISTRY.length}，基线 ${EXPECTED_COUNT}）。增删条目是正常维护，但必须是有意的：确认后同步更新本文件的 EXPECTED_COUNT。`,
  );
});

test('② id 序列：顺序即投放优先级，不许静默重排', () => {
  assert.equal(
    sha(PAYLOAD_REGISTRY.map((e) => e.id)),
    EXPECTED_ID_SHA,
    'id 序列与基线不一致（新增/删除/重排了条目）。确认意图后更新 EXPECTED_ID_SHA。',
  );
});

test('③ 内容指纹：任何字段任何字符变化都会红', () => {
  assert.equal(
    sha(dataOf(PAYLOAD_REGISTRY)),
    EXPECTED_DATA_SHA,
    '注册表内容与基线不一致。先 `git diff server/src/engine/payloads/registry.json`（每条一行，能直接定位）确认改动是否符合意图；确认后更新 EXPECTED_DATA_SHA。',
  );
});

test('note 与行为指纹解耦：改注记不应要求改指纹', () => {
  const payload = dataOf(PAYLOAD_REGISTRY);
  // 两边都要走 dataOf 剥 note —— 直接拿带 note 的列表比指纹是错的（首版就写错过，
  // 被这条测试自己抓出来：note 明明不参与指纹，却因为没剥而报了不等价）
  const withNotes = PAYLOAD_REGISTRY.map((e) => ({ ...e, note: '任意注记' }));
  assert.equal(sha(dataOf(withNotes)), sha(payload));
});
