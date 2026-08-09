import type { ReportModel } from './types';
import { RISK_LABEL, TECHNIQUE_LABEL } from './constants';
import { toPng } from 'html-to-image';
import { jsPDF } from 'jspdf';

// ── 报告导出工具（纯前端生成，不依赖后端 /export 端点）──────────────
// 对标 sqlmap 多格式报告：在既有 JSON/HTML（走后端）之外，补充 Markdown 与 CSV
// 两种人类/表格友好格式，便于粘贴到工单、Excel 审计或版本管理 diff。
// 覆盖：目标信息 / 注入点 / 漏洞 / 二阶自动发现 / 提取数据 / OOB 回连 / 安全间隔告警 / WAF 标注指纹，
// 与后端 HTML 报告（ReportGenerator）的展示维度一致。

function fmtTime(s: string | null): string {
  if (!s) return '—';
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? s : d.toLocaleString();
}

/** 定位某个注入点参数名（漏洞 → pointId → points 查找） */
function paramOf(report: ReportModel, pointId: string): string {
  return report.points.find((p) => p.id === pointId)?.param ?? pointId;
}

/** 生成 Markdown 报告（中文、章节化、表格化） */
export function reportToMarkdown(r: ReportModel): string {
  const lines: string[] = [];
  lines.push('# SQL 注入检测报告');
  lines.push('');
  lines.push('| 字段 | 值 |');
  lines.push('| --- | --- |');
  lines.push(`| 扫描 ID | ${r.scanId} |`);
  lines.push(`| 目标 | ${r.target.baseUrl} |`);
  lines.push(`| 请求方法 | ${r.target.method} |`);
  lines.push(`| 开始时间 | ${fmtTime(r.startedAt)} |`);
  lines.push(`| 结束时间 | ${fmtTime(r.finishedAt)} |`);
  lines.push(`| 识别数据库 | ${r.dbms ?? '未知'} |`);
  lines.push(`| 总体风险 | ${RISK_LABEL[r.riskLevel] ?? r.riskLevel} |`);
  lines.push('');

  // 一、注入点清单
  lines.push(`## 一、注入点清单（共 ${r.points.length} 个）`);
  lines.push('');
  lines.push('| # | 位置 | 参数 | 原始值 | 是否存储点 | 存储分类 | 确认漏洞 |');
  lines.push('| --- | --- | --- | --- | --- | --- | --- |');
  r.points.forEach((p, i) => {
    const vuln = r.vulns.find((v) => v.pointId === p.id);
    lines.push(
      `| ${i + 1} | ${p.location} | ${p.param} | ${p.originalValue} | ${
        p.isStorePoint ? '是' : '否'
      } | ${p.storeKind ?? '—'} | ${vuln ? '是' : '否'} |`,
    );
  });
  lines.push('');

  // 二、漏洞清单
  lines.push(`## 二、漏洞清单（共 ${r.vulns.length} 个）`);
  lines.push('');
  lines.push('| # | 注入点参数 | 技术 | 数据库 | 风险 | 载荷 |');
  lines.push('| --- | --- | --- | --- | --- | --- |');
  r.vulns.forEach((v, i) => {
    const payloads = (v.payloads || []).join(' ; ');
    lines.push(
      `| ${i + 1} | ${paramOf(r, v.pointId)} | ${TECHNIQUE_LABEL[v.technique] ?? v.technique} | ${
        v.dbms ?? '—'
      } | ${RISK_LABEL[v.riskLevel] ?? v.riskLevel} | ${payloads} |`,
    );
  });
  lines.push('');

  // 三、二阶自动发现
  const disc = r.summary?.secondOrderDiscovery;
  if (disc || r.points.some((p) => p.isStorePoint)) {
    lines.push('## 三、二阶自动发现');
    lines.push('');
    if (disc) {
      lines.push(
        `自动发现：从 ${disc.candidates.length} 个候选链接中确认 ${disc.confirmed.length} 个会回显存储内容的触发页。`,
      );
      if (disc.confirmed.length) {
        lines.push('');
        lines.push('确认触发页：');
        disc.confirmed.forEach((u) => lines.push(`- ${u}`));
      }
    }
    const stores = r.points.filter((p) => p.isStorePoint);
    if (stores.length) {
      lines.push('');
      lines.push(`识别存储点 ${stores.length} 个：${stores.map((s) => s.param).join('、')}`);
    }
    lines.push('');
  }

  // 四、提取数据
  if (r.data) {
    lines.push('## 四、提取数据（拖库）');
    lines.push('');
    lines.push(`数据库（${r.data.databases.length}）：${r.data.databases.join('、')}`);
    const tblCount = Object.keys(r.data.tables).length;
    const rowCount = Object.values(r.data.rows).reduce((acc, rows) => acc + rows.length, 0);
    lines.push('');
    lines.push(`数据表 ${tblCount} 个，提取行数 ${rowCount}。`);
    lines.push('');
  }

  // 五、OOB 带外回连确认
  const oobVulns = r.vulns.filter((v) => v.oob);
  if (oobVulns.length) {
    lines.push('## OOB 带外回连确认');
    lines.push('');
    lines.push(
      `共 ${oobVulns.length} 个漏洞经带外通道（目标 DBMS 主动回连接收端）确认无回显注入成立；仅确认、不自动拖库。`,
    );
    lines.push('');
    oobVulns.forEach((v) => {
      lines.push(
        `- 注入点参数 **${paramOf(r, v.pointId)}**（${
          TECHNIQUE_LABEL[v.technique] ?? v.technique
        }）：token \`${v.oob!.token}\`、回连地址 \`${v.oob!.callback}\``,
      );
    });
    lines.push('');
  }

  // 六、安全间隔探测告警
  const alerts = r.summary?.safeProbeAlerts;
  if (alerts && alerts.length) {
    lines.push('## 安全间隔探测告警');
    lines.push('');
    lines.push(
      `共 ${alerts.length} 条：安全间隔探测响应偏离基线，当前批次检测结果可能失真，建议复核。`,
    );
    lines.push('');
    lines.push('| # | URL | 原因 | 基线(状态/长度) | 实际(状态/长度) | 时间 |');
    lines.push('| --- | --- | --- | --- | --- | --- |');
    alerts.forEach((a, i) => {
      lines.push(
        `| ${i + 1} | ${a.url} | ${a.reason} | ${a.baselineStatus ?? '—'}/${
          a.baselineLen ?? '—'
        } | ${a.actualStatus ?? '—'}/${a.actualLen ?? '—'} | ${fmtTime(a.ts)} |`,
      );
    });
    lines.push('');
  }

  // 七、WAF 规避与指纹
  const wafEvasion = r.summary?.wafEvasion;
  const wafDetected = r.summary?.wafDetected;
  if (wafEvasion?.tamper?.enabled || (wafDetected && wafDetected.length)) {
    lines.push('## WAF 规避与指纹');
    lines.push('');
    if (wafEvasion?.tamper?.enabled) {
      const t = wafEvasion.tamper;
      lines.push(`Tamper 组合：${(t.plugins || []).join(' → ') || '无'}（强度：${t.intensity ?? 'medium'}）`);
      lines.push('');
    }
    if (wafDetected && wafDetected.length) {
      lines.push('识别到 WAF：');
      wafDetected.forEach((w) =>
        lines.push(`- ${w.vendor}（置信度 ${Math.round((w.confidence ?? 0) * 100)}%，证据：${w.evidence}）`),
      );
      lines.push('');
    }
  }

  return lines.join('\n');
}

/** CSV 字段转义：含逗号/引号/换行时用双引号包裹，内部引号转义为双引号 */
function csvEscape(value: string | number | null | undefined): string {
  const s = value === null || value === undefined ? '' : String(value);
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

/** 生成 CSV 报告：以「注入点」为主表，附带其确认漏洞与 OOB 信息（一行一注入点，最利于 Excel 审计） */
export function reportToCsv(r: ReportModel): string {
  const header = [
    '注入点ID',
    '位置',
    '参数',
    '原始值',
    '是否存储点',
    '存储分类',
    '确认漏洞',
    '技术',
    '数据库',
    '风险等级',
    '载荷',
    '描述',
    'OOB Token',
    'OOB 回连地址',
  ];
  const rows: string[] = [header.map(csvEscape).join(',')];

  for (const p of r.points) {
    const pointVulns = r.vulns.filter((v) => v.pointId === p.id);
    const vuln = pointVulns[0]; // 首个漏洞：用于技术/风险/载荷/描述（与 Markdown 漏洞清单一致）
    const oobVuln = pointVulns.find((v) => v.oob); // 注入点→漏洞为一对多，OOB 可能非首个命中，须单独检索
    const row = [
      p.id,
      p.location,
      p.param,
      p.originalValue,
      p.isStorePoint ? '是' : '否',
      p.storeKind ?? '',
      vuln ? '是' : '否',
      vuln ? TECHNIQUE_LABEL[vuln.technique] ?? vuln.technique : '',
      vuln?.dbms ?? '',
      vuln ? RISK_LABEL[vuln.riskLevel] ?? vuln.riskLevel : '',
      vuln ? (vuln.payloads || []).join(' ; ') : '',
      vuln ? vuln.description : '',
      oobVuln?.oob?.token ?? '',
      oobVuln?.oob?.callback ?? '',
    ];
    rows.push(row.map(csvEscape).join(','));
  }

  // 安全间隔探测告警（独立块，标题行 + 表头 + 明细）
  const alerts = r.summary?.safeProbeAlerts;
  if (alerts && alerts.length) {
    rows.push('');
    rows.push(csvEscape(`安全间隔探测告警（${alerts.length} 条）`));
    rows.push(['URL', '原因', '基线状态', '基线长度', '实际状态', '实际长度', '时间'].map(csvEscape).join(','));
    alerts.forEach((a) => {
      rows.push(
        [
          a.url,
          a.reason,
          a.baselineStatus ?? '',
          a.baselineLen ?? '',
          a.actualStatus ?? '',
          a.actualLen ?? '',
          fmtTime(a.ts),
        ]
          .map(csvEscape)
          .join(','),
      );
    });
  }

  // WAF 规避与指纹（独立块）
  const wafEvasion = r.summary?.wafEvasion;
  const wafDetected = r.summary?.wafDetected;
  if (wafEvasion?.tamper?.enabled || (wafDetected && wafDetected.length)) {
    rows.push('');
    rows.push(csvEscape('WAF 规避与指纹'));
    if (wafEvasion?.tamper?.enabled) {
      const t = wafEvasion.tamper;
      rows.push(['Tamper 组合', (t.plugins || []).join(' → ') || '无'].map(csvEscape).join(','));
      rows.push(['强度', t.intensity ?? 'medium'].map(csvEscape).join(','));
    }
    if (wafDetected && wafDetected.length) {
      rows.push(csvEscape(`WAF 指纹识别（${wafDetected.length} 家）`));
      rows.push(['厂商', '置信度', '证据'].map(csvEscape).join(','));
      wafDetected.forEach((w) => {
        rows.push([w.vendor, `${Math.round((w.confidence ?? 0) * 100)}%`, w.evidence].map(csvEscape).join(','));
      });
    }
  }

  return rows.join('\r\n');
}

/** 纯前端触发文本下载（Blob + 临时锚点）。测试环境可 mock URL.createObjectURL。 */
export function downloadText(filename: string, text: string, mime = 'text/plain;charset=utf-8'): void {
  if (typeof document === 'undefined' || typeof URL === 'undefined' || typeof URL.createObjectURL !== 'function') {
    return;
  }
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  if (typeof URL.revokeObjectURL === 'function') URL.revokeObjectURL(url);
}

/**
 * 纯前端 PDF 导出：把指定 DOM 节点（通常是报告内容根）经 html-to-image 栅格化为 PNG，
 * 再按 A4 页面高度用 canvas 逐页切片写入多页 jsPDF。
 *
 * 为什么用「DOM 栅格化 + 截图拼页」而非「jsPDF 文本 API」：
 *  - 报告含中文、MUI 组件、拓扑图（react-flow/SVG），jsPDF 原生文本 API 对 CJK 需嵌入字体、对
 *    复杂 DOM 排版支持差；栅格化天然保留现有视觉（与拓扑图「导出 PNG」同机制），零字体缺失风险。
 *  - 切片算法：按 A4 比例（mm）把整图高度映射为若干页，每页用 canvas 裁出对应纵向区域再 addImage，
 *    避免内容被拦腰截断（jsPDF 的 addImage 不支持源区域裁剪，故用 canvas 预裁）。
 *  - 比例仅依赖栅格化后的真实像素（img.naturalWidth/Height），不依赖 DOM 布局尺寸，规避除零。
 *
 * @param node  要导出的 DOM 根（调用方在按钮点击时 ref 指向报告内容容器；不在 store 里）
 * @param filename 下载文件名（.pdf）
 * @returns Promise<void>（便于测试 await）
 */
export async function downloadPdf(node: HTMLElement, filename: string): Promise<void> {
  // 注：PDF 导出走 jsPDF.save（浏览器原生下载），不依赖 URL.createObjectURL；
  // 仅需在浏览器 DOM 环境下运行（canvas/Image 需真实浏览器）。
  if (typeof document === 'undefined') {
    return;
  }
  // 1) 栅格化整个报告节点为高清 PNG（倍数 2 保证文字清晰；背景白底便于打印）
  //    filter 排除打印隐藏区（.rp-no-print）与 PDF 专属排除标记（data-pdf-exclude，
  //    即目录锚点栏与「导出」按钮区自身），避免导出按钮/锚点出现在本导出件里。
  const dataUrl = await toPng(node, {
    pixelRatio: 2,
    backgroundColor: '#ffffff',
    cacheBust: true,
    filter: (el) => {
      if (!(el instanceof HTMLElement)) return true;
      if (el.classList?.contains('rp-no-print')) return false;
      if (el.hasAttribute?.('data-pdf-exclude')) return false;
      return true;
    },
  });

  // 2) 加载栅格化结果，取得真实像素尺寸（切片比例的唯一权威来源）
  //    注意：先挂 onload/onerror 再赋值 src（真实浏览器加载异步无碍；同步 mock 也需先挂后触发）
  const img = new Image();
  await new Promise<void>((resolve, reject) => {
    img.onload = () => resolve();
    img.onerror = () => reject(new Error('PDF 栅格化失败：图片加载错误'));
    img.src = dataUrl;
  });
  const fullPxW = img.naturalWidth;
  const fullPxH = img.naturalHeight;

  const pdf = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageW = pdf.internal.pageSize.getWidth(); // 默认 210mm
  const pageH = pdf.internal.pageSize.getHeight(); // 默认 297mm
  const margin = 8; // 页边距（mm），避免内容贴边
  const imgW = pageW - margin * 2;
  const contentH = pageH - margin * 2;

  // 真实像素 → 输出 mm 比例；若栅格化异常（0 像素）则兜底为单页空白 A4
  const pxPerMm = fullPxW > 0 ? fullPxW / imgW : 0;
  const imgH = pxPerMm > 0 ? fullPxH / pxPerMm : contentH;

  let rendered = 0; // 已覆盖的输出高度（mm）
  let pageIndex = 0;
  while (rendered < imgH - 0.01) {
    const sliceHmm = Math.min(imgH - rendered, contentH); // 本页可容纳内容高度
    const srcY = rendered * pxPerMm; // 本页在源图纵向起点（px）
    const srcH = sliceHmm * pxPerMm; // 本页源图纵向高度（px）

    // 用 canvas 裁出本页区域（白底，避免透明背景在 PDF 查看器里发黑）
    const canvas = document.createElement('canvas');
    canvas.width = fullPxW;
    canvas.height = Math.max(1, Math.round(srcH));
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('PDF 切片失败：无法获取 canvas 2D 上下文');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(img, 0, srcY, fullPxW, srcH, 0, 0, canvas.width, canvas.height);
    const pageData = canvas.toDataURL('image/png');

    if (pageIndex > 0) pdf.addPage();
    pdf.addImage(pageData, 'PNG', margin, margin, imgW, sliceHmm);
    rendered += sliceHmm;
    pageIndex++;
    if (pageIndex > 100) break; // 安全阀：极端长报告保护（>100 页不再无限循环）
  }

  // 3) 输出并触发下载（jsPDF 直接 save → 走浏览器下载，与现有 4 个下载一致）
  pdf.save(filename);
}
