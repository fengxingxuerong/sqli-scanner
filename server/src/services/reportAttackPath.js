// reportAttackPath.js —— 攻击路径叙事：把报告数据渲染成「从入口到影响面」的链路
// ============================================================================
// 背景（`docs/全方面优化方案` E3）：报告四件套里 CVSS / PoC 复现包 / 管理层摘要**都已实现**，
// 唯独缺「攻击路径叙事」—— 读者看到的是一张漏洞列表，而不是「从哪个入口、经什么通道、
// 拿到了什么、影响边界在哪」的一条链。
//
// ■ 数据完全来自既有 report（**纯只读派生，不新增任何探测**）
//   report.target（入口）→ report.points（注入点）→ report.vulns（技术通道/DBMS/风险）
//   → report.data.rows（拖库树）→ 影响面。
//
// ■ 为什么用**内联 SVG** 而不是 mermaid
//   报告是离线交付物（客户可能在内网、无外网），mermaid 依赖 CDN 的 JS —— 断网即整张图不显示。
//   内联 SVG 自包含、可打印、可被邮件正文带入。markdown 侧另给 mermaid 代码块
//   （渲染器支持时更好看，不支持时是纯文本，不会「坏掉」）。
//
// ■ 诚实边界（沿用红线「不谎报」）
//   路径层级**只按报告里真实存在的证据推进**：没有 data.rows 就停在「已证实可注入」，
//   **不虚构**「已提权/已写入 shell」。止步时会显式写明"利用链未在本报告中执行或未留存证据"。
// ============================================================================
import { esc, mdText } from './reportHtml.js';

/** 路径层级（只按证据推进，见文件头"诚实边界"） */
export const PATH_LEVELS = {
  NONE: 'none',       // 未发现注入
  PROBE: 'probe',     // 已证实可注入（无数据提取证据）
  EXTRACT: 'extract', // 已读取到业务数据
  EXPLOIT: 'exploit', // 有堆叠/高危利用证据
};

const LEVEL_LABEL = {
  [PATH_LEVELS.NONE]: '未发现可利用入口',
  [PATH_LEVELS.PROBE]: '已证实可注入',
  [PATH_LEVELS.EXTRACT]: '已读取业务数据',
  [PATH_LEVELS.EXPLOIT]: '存在高危利用证据',
};

/** 文本截断（SVG 不做自动换行，过长会溢出卡片） */
function clip(s, max = 56) {
  const t = String(s ?? '');
  return t.length > max ? t.slice(0, max - 1) + '…' : t;
}

/** 入口展示串（method + host/path） */
function entryText(target) {
  if (!target || typeof target !== 'object') return '(未记录目标)';
  const method = String(target.method || 'GET').toUpperCase();
  let url = target.url || target.baseUrl || '';
  try {
    const u = new URL(url);
    url = u.host + u.pathname;
  } catch {
    /* 非完整 URL：原样展示 */
  }
  return `${method} ${url || '(未记录 URL)'}`;
}

/** 某注入点的技术通道集合 */
function techniquesOf(report, pointId) {
  const out = new Set();
  for (const v of report?.vulns || []) {
    if (v && v.pointId === pointId && v.technique) out.add(v.technique);
  }
  return [...out];
}

/**
 * 构建攻击路径。纯只读、全程容错 —— report 可缺任意字段。
 * @param {object} report ReportGenerator.build 产物（或 ScanManager.getReport）
 * @returns {{stages:Array<{kind:string,title:string,items:Array<{label:string,detail:string}>}>, level:string, levelLabel:string, note:string|null, reached:string[]}}
 */
export function buildAttackPath(report) {
  const r = report && typeof report === 'object' ? report : {};
  const vulns = Array.isArray(r.vulns) ? r.vulns.filter((v) => v && typeof v === 'object') : [];
  const points = Array.isArray(r.points) ? r.points.filter((p) => p && typeof p === 'object') : [];
  const rows = r?.data && typeof r.data === 'object' && r.data.rows && typeof r.data.rows === 'object'
    ? r.data.rows
    : null;

  const hitPointIds = [...new Set(vulns.map((v) => v.pointId).filter(Boolean))];
  const dbms = [...new Set(vulns.map((v) => v.dbms).filter(Boolean))].join(' / ') || null;

  // —— 层级判定：只按证据 ——
  const hasStacked = vulns.some((v) => v.technique === 'stacked');
  const hasCritical = vulns.some((v) => String(v.riskLevel || '').toLowerCase() === 'critical');
  const tableCount = rows ? Object.values(rows).filter((v) => Array.isArray(v) && v.length).length : 0;
  let level = PATH_LEVELS.NONE;
  if (vulns.length > 0) level = PATH_LEVELS.PROBE;
  if (tableCount > 0) level = PATH_LEVELS.EXTRACT;
  if (level === PATH_LEVELS.EXTRACT && (hasStacked || hasCritical)) level = PATH_LEVELS.EXPLOIT;

  const stages = [];

  // ① 入口
  stages.push({
    kind: 'target',
    title: '入口',
    items: [{
      label: entryText(r.target),
      detail: `${points.length} 个待测参数${r.target?.config?.scope?.length ? ` · 授权范围 ${r.target.config.scope.join(',')}` : ''}`,
    }],
  });

  // ② 命中注入点
  if (hitPointIds.length) {
    const shown = hitPointIds.slice(0, 4).map((pid) => {
      const p = points.find((x) => String(x.id) === String(pid)) || {};
      const tech = techniquesOf(r, pid);
      const loc = p.location ? String(p.location) : null;
      const param = p.param || p.name || pid;
      const detail = [loc, tech.join('/')].filter(Boolean).join(' · ') || '通道未记录';
      return { label: clip(String(param), 28), detail };
    });
    if (hitPointIds.length > shown.length) {
      shown.push({ label: `另有 ${hitPointIds.length - shown.length} 个命中点`, detail: '见漏洞明细表' });
    }
    stages.push({ kind: 'point', title: `命中注入点（${hitPointIds.length}）`, items: shown });
  }

  // ③ 可用通道
  if (vulns.length) {
    const byTech = new Map();
    for (const v of vulns) {
      const t = v.technique || 'unknown';
      byTech.set(t, (byTech.get(t) || 0) + 1);
    }
    stages.push({
      kind: 'technique',
      title: '可用通道',
      items: [...byTech.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([t, n]) => ({ label: t, detail: `${n} 处命中${dbms ? ` · 目标 DBMS ${dbms}` : ''}` })),
    });
  }

  // ④ 数据获取（只在有证据时出现）
  if (tableCount > 0) {
    const rowCount = Object.values(rows).reduce((n, v) => n + (Array.isArray(v) ? v.length : 0), 0);
    const sample = Object.entries(rows)
      .filter(([, v]) => Array.isArray(v) && v.length)
      .slice(0, 3)
      .map(([k]) => k);
    stages.push({
      kind: 'extraction',
      title: '数据获取',
      items: [
        { label: `${tableCount} 张表 / ${rowCount} 行`, detail: '已落入交付包（report.data）' },
        ...(sample.length ? [{ label: sample.join('、'), detail: '样本表（最多列 3 张）' }] : []),
      ],
    });
  }

  // ⑤ 影响定性（总是给结论段）
  const highest = vulns
    .map((v) => String(v.riskLevel || '').toLowerCase())
    .sort((a, b) => ['critical', 'high', 'medium', 'low'].indexOf(a) - ['critical', 'high', 'medium', 'low'].indexOf(b))[0];
  stages.push({
    kind: 'impact',
    title: '影响定性',
    items: [{
      label: LEVEL_LABEL[level],
      detail: level === PATH_LEVELS.NONE
        ? '本报告未记录可利用路径'
        : [
          highest ? `最高风险等级 ${highest}` : null,
          tableCount > 0 ? '业务数据可被读取' : null,
          hasStacked ? '存在堆叠注入证据（可多语句执行）' : null,
        ].filter(Boolean).join(' · '),
    }],
  });

  // —— 诚实边界 ——
  let note = null;
  if (level === PATH_LEVELS.PROBE) {
    note = '路径止于「已证实可注入」：本报告未执行数据提取（或提取无结果），因此**不代表目标仅到此为止**。';
  } else if (level === PATH_LEVELS.EXTRACT) {
    note = '路径止于「已读取业务数据」：提权 / 写文件 / 命令执行等利用链**未在本报告中执行或未留存证据**。';
  } else if (level === PATH_LEVELS.NONE) {
    note = '未记录可利用路径 —— 这表示本次扫描未取得证据，不等于目标安全（见报告「不谎报」声明）。';
  }

  return {
    stages,
    level,
    levelLabel: LEVEL_LABEL[level],
    note,
    reached: stages.map((s) => s.kind),
  };
}

/**
 * markdown 渲染：mermaid 代码块（渲染器支持时成图）+ 步骤列表（任何渲染器都可读）。
 * ⚠️ 返回**行数组**（与 `reportPoC.pocMarkdown` 的契约一致，调用处 `md.push(...lines)`）——
 *    首版返回单个字符串，会让 ReportGenerator 侧多出一句 `.split('\n')`，
 *    正是"两处口径漂移"的温床，故对齐为数组。
 * @param {object} report
 * @returns {string[]}
 */
export function attackPathMarkdown(report) {
  const p = buildAttackPath(report);
  const lines = [];
  lines.push('```mermaid');
  lines.push('flowchart TD');
  const ids = p.stages.map((_, i) => `S${i + 1}`);
  for (let i = 0; i < p.stages.length; i++) {
    const s = p.stages[i];
    // items 的 label/detail 里是**参数名、DBMS 串、目标库表名**（:109/:147），全部目标可控。
    // SVG 侧走 esc（:291），markdown 侧此前是裸内插：mermaid 默认 htmlLabels 会渲染行内 HTML，
    // 下面的编号清单更是普通 markdown 正文 —— 两者都是「打开报告的机器」执行目标字符串。
    const label = mdText(`${s.title}\\n${s.items.map((it) => it.label).join(' / ')}`).replace(/"/g, "'");
    lines.push(`  ${ids[i]}["${clip(label, 90)}"]`);
  }
  for (let i = 0; i < ids.length - 1; i++) lines.push(`  ${ids[i]} --> ${ids[i + 1]}`);
  lines.push('```');
  lines.push('');
  p.stages.forEach((s, i) => {
    lines.push(`${i + 1}. **${mdText(s.title)}**`);
    for (const it of s.items) lines.push(`   - ${mdText(it.label)}${it.detail ? ` —— ${mdText(it.detail)}` : ''}`);
  });
  if (p.note) {
    lines.push('');
    lines.push(`> ⚠️ ${p.note}`);
  }
  return lines;
}

/**
 * HTML 渲染：自包含内联 SVG 纵向流程图（无外部依赖，断网/打印均可读）。
 * @param {object} report
 * @returns {string}
 */
export function attackPathHtml(report) {
  const p = buildAttackPath(report);
  const CARD_X = 64;
  const CARD_W = 576;
  const LINE_H = 19;
  const PAD = 10;
  const GAP = 30;
  const HEAD = 20;

  // 先算高度（两趟：先量后画，避免用固定高度裁切）
  let y = 8;
  const layout = [];
  for (const s of p.stages) {
    const cardH = s.items.length * LINE_H + PAD * 2;
    layout.push({ stage: s, top: y + HEAD, cardH });
    y += HEAD + cardH + GAP;
  }
  const totalH = y + 4;

  const parts = [];
  parts.push(
    `<svg viewBox="0 0 680 ${totalH}" width="100%" role="img" aria-label="攻击路径图" ` +
      `style="display:block;background:var(--card);border:1px solid var(--hairline-strong);border-radius:6px">`
  );
  parts.push(
    `<defs><marker id="apArrow" markerWidth="9" markerHeight="9" refX="7" refY="3" orient="auto">` +
      `<path d="M0,0 L0,6 L7,3 z" fill="#b8c4ce"/></marker></defs>`
  );

  layout.forEach((row, i) => {
    const { stage, top, cardH } = row;
    const cx = 34; // 序号圆/连接线所在竖轴
    const cy = top + 14;

    // 连接线（下一层）
    if (i < layout.length - 1) {
      const nextTop = layout[i + 1].top;
      parts.push(
        `<line x1="${cx}" y1="${cy + 10}" x2="${cx}" y2="${nextTop - 14}" ` +
          `stroke="#b8c4ce" stroke-width="1.5" marker-end="url(#apArrow)"/>`
      );
    }
    // 序号圆
    parts.push(
      `<circle cx="${cx}" cy="${cy}" r="11" fill="#e3eff1" stroke="#0f5e6b" stroke-width="1"/>` +
        `<text x="${cx}" y="${cy + 4}" text-anchor="middle" font-family="Segoe UI,Microsoft YaHei,sans-serif" ` +
        `font-size="12" font-weight="600" fill="#0f5e6b">${i + 1}</text>`
    );
    // 阶段标题
    parts.push(
      `<text x="${CARD_X}" y="${top}" font-family="Segoe UI,Microsoft YaHei,sans-serif" ` +
        `font-size="13" font-weight="600" fill="#1c2430">${esc(stage.title)}</text>`
    );
    // 卡片
    parts.push(
      `<rect x="${CARD_X}" y="${top + 6}" width="${CARD_W}" height="${cardH}" rx="6" ` +
        `fill="#ffffff" stroke="#d7dee5"/>`
    );
    // 条目
    stage.items.forEach((it, j) => {
      const ly = top + 6 + PAD + 13 + j * LINE_H;
      parts.push(
        `<text x="${CARD_X + 14}" y="${ly}" font-family="Cascadia Code,JetBrains Mono,Consolas,monospace" ` +
          `font-size="12.5" fill="#0f5e6b">${esc(clip(it.label))}</text>`
      );
      if (it.detail) {
        parts.push(
          `<text x="${CARD_X + 14}" y="${ly + 12}" font-family="Segoe UI,Microsoft YaHei,sans-serif" ` +
            `font-size="11" fill="#5a6b7d">${esc(clip(it.detail, 72))}</text>`
        );
      }
    });
  });

  parts.push('</svg>');

  const noteHtml = p.note
    ? `<p class="meta" style="margin-top:8px">⚠️ ${esc(p.note)}</p>`
    : '';

  return `<h2>攻击路径</h2>
<div class="kicker">attack path · ${esc(p.level)}</div>
${parts.join('\n')}
${noteHtml}`;
}

export default { buildAttackPath, attackPathMarkdown, attackPathHtml, PATH_LEVELS };
