// 报告生成器：汇总 ReportModel、风险定级、JSON/HTML 导出
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// 引擎版本（读取 server/package.json，失败回退 unknown），仅用于报告页脚展示
let ENGINE_VERSION = 'unknown';
try {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const pkg = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf8'));
  ENGINE_VERSION = pkg.version || 'unknown';
} catch {
  // 版本读取失败不影响报告生成
}

export class ReportGenerator {
  /**
   * 构造报告
   * @param {string} scanId
   * @param {object} target
   * @param {object[]} points
   * @param {object[]} vulns
   * @param {object|null} data
   */
  build(scanId, target, points, vulns, data) {
    const riskLevel = this.riskOf(vulns, data);
    return {
      scanId,
      target,
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      dbms: [...new Set(vulns.map((v) => v.dbms).filter(Boolean))].join(', ') || null,
      points,
      vulns,
      data: data || null,
      riskLevel,
      summary: {
        totalPoints: points.length,
        totalVulns: vulns.length,
        byTechnique: this._countBy(vulns, 'technique'),
        byRisk: this._countBy(vulns, 'riskLevel'),
      },
    };
  }

  // 风险定级：可提取=Critical / 堆叠=Critical / 可回显=High / 仅盲注=Medium / 疑似=Low
  riskOf(vulns, data) {
    if (data && this._hasData(data)) return 'Critical';
    // 堆叠注入可进一步用于写文件/命令执行，风险最高，置于所有判定之前
    if (vulns.some((v) => v.technique === 'stacked')) return 'Critical';
    if (
      vulns.some(
        (v) => v.technique === 'union' || v.technique === 'error' || v.technique === 'second_order'
      )
    ) {
      return 'High';
    }
    if (vulns.some((v) => v.technique === 'boolean' || v.technique === 'time')) {
      return 'Medium';
    }
    // OOB 带外仅确认注入存在（不进拖库/二分提取），风险等同盲注 → Medium
    if (vulns.some((v) => v.technique === 'oob')) {
      return 'Medium';
    }
    if (vulns.length > 0) return 'Low';
    return 'Low';
  }

  _hasData(data) {
    return !!(
      (data.databases && data.databases.length) ||
      (data.tables && Object.keys(data.tables).length) ||
      (data.rows && Object.keys(data.rows).length)
    );
  }

  _countBy(arr, key) {
    const m = {};
    for (const x of arr) m[x[key]] = (m[x[key]] || 0) + 1;
    return m;
  }

  // 导出 JSON
  toJSON(report) {
    return JSON.stringify(report, null, 2);
  }

  // 导出 HTML（内联样式，离线可打开）
  toHTML(report) {
    const rows = (report.vulns || [])
      .map(
        (v) => `<tr>
        <td>${v.pointId}</td>
        <td>${v.technique}</td>
        <td>${v.dbms || '-'}</td>
        <td class="${v.riskLevel.toLowerCase()}">${v.riskLevel}</td>
        <td>${this._escape(v.description || '')}${
          v.oob
            ? `<br><span style="color:#c62828;font-weight:bold">带外回连确认（OOB）</span><br>token：${this._escape(v.oob.token)}<br>回连：${this._escape(v.oob.callback)}`
            : ''
        }</td>
      </tr>`
      )
      .join('');
    const payloads = (report.vulns || [])
      .flatMap((v) => v.payloads || [])
      .map((p) => '• ' + this._escape(p))
      .join('\n');

    // 安全间隔探测告警（对标 sqlmap --safe-url 偏离告警；仅记录不阻断）
    const alertItems = (report.summary && report.summary.safeProbeAlerts) || [];
    const alertsHtml = alertItems.length
      ? `<h2 id="sec-alerts">安全间隔探测告警（${alertItems.length} 条）</h2>
      <div style="border:1px solid #ef6c00;border-radius:6px;padding:10px;background:#fff8f0">
        <p class="meta">扫描期间安全 URL 偏离基线，说明目标可能被 WAF/IPS 拦截、会话失效或触发限流，当前批次检测结果可能失真，建议复核命中结论。</p>
        <ul style="margin:6px 0;padding-left:18px">
          ${alertItems
            .map(
              (a) => `<li style="margin-bottom:6px">
            <b>${this._escape(a.url)}</b><br>
            ${this._escape(a.reason)}<br>
            <span class="meta">基线 ${a.baselineStatus}（${a.baselineLen}B）→ 实际 ${a.actualStatus}（${a.actualLen}B）${
              a.ts ? ` · ${this._escape(a.ts)}` : ''
            }</span>
          </li>`
            )
            .join('')}
        </ul>
      </div>`
      : '';

    // 扫描统计（技术分布 / 风险分布）
    const byTech = (report.summary && report.summary.byTechnique) || {};
    const byRisk = (report.summary && report.summary.byRisk) || {};
    const statsHtml = `<h2 id="sec-stats">扫描统计</h2>
      <p class="meta">注入点：${(report.points || []).length} · 漏洞：${(report.vulns || []).length}</p>
      <p class="meta">按技术：${Object.keys(byTech).length ? Object.entries(byTech).map(([k, v]) => `${this._escape(k)}:${v}`).join(' / ') : '无'}</p>
      <p class="meta">按风险：${Object.keys(byRisk).length ? Object.entries(byRisk).map(([k, v]) => `${this._escape(k)}:${v}`).join(' / ') : '无'}</p>`;

    // WAF 规避与指纹标注（对标前端 ReportPage WAF 区块）
    const wafEvasion = report.summary && report.summary.wafEvasion;
    const wafDetected = (report.summary && report.summary.wafDetected) || [];
    const wafParts = [];
    if (wafEvasion && wafEvasion.tamper && wafEvasion.tamper.enabled) {
      wafParts.push(`tamper 组合：${this._escape((wafEvasion.tamper.plugins || []).join(' → '))}（强度：${this._escape(wafEvasion.tamper.intensity || 'medium')}）`);
    }
    if (Array.isArray(wafDetected) && wafDetected.length) {
      wafParts.push(`识别到 WAF：${wafDetected.map((w) => `${this._escape(w.vendor)}(${this._escape(String(w.confidence))})`).join('、')}`);
    }
    const wafHtml = wafParts.length
      ? `<h2 id="sec-waf">WAF 规避与指纹</h2>
      <div style="border:1px solid #1565c0;border-radius:6px;padding:10px;background:#f0f6ff">
        <ul style="margin:6px 0;padding-left:18px">
          ${wafParts.map((p) => `<li style="margin-bottom:4px">${p}</li>`).join('')}
        </ul>
      </div>`
      : '';

    // 目录锚点（仅列出实际存在的区块，供跳转与打印导航）
    const toc = [
      { id: 'sec-stats', title: '扫描统计' },
      ...(wafParts.length ? [{ id: 'sec-waf', title: 'WAF 规避与指纹' }] : []),
      { id: 'sec-vulns', title: '漏洞清单' },
      ...(alertItems.length
        ? [{ id: 'sec-alerts', title: `安全间隔探测告警（${alertItems.length} 条）` }]
        : []),
      { id: 'sec-payloads', title: 'Payload 示例' },
    ];
    const tocHtml = `<nav class="toc" aria-label="目录">
      <div class="toc-title">目录</div>
      <ul>${toc.map((t) => `<li><a href="#${t.id}">${this._escape(t.title)}</a></li>`).join('')}</ul>
    </nav>`;

    // 风险等级配色图例（与 CSS .critical/.high/.medium/.low 配色一致，便于打印后快速识别风险）
    const legendHtml = `<div class="legend" aria-label="风险等级图例">
      <span class="lg critical">Critical</span>
      <span class="lg high">High</span>
      <span class="lg medium">Medium</span>
      <span class="lg low">Low</span>
    </div>`;

    // 页脚：生成时间（report.finishedAt）+ 引擎版本 + 自动生成声明
    const finishedAt = report.finishedAt ? new Date(report.finishedAt).toLocaleString('zh-CN') : '-';
    const footerHtml = `<footer class="rp-footer">生成时间：${this._escape(finishedAt)} · 引擎版本 v${this._escape(ENGINE_VERSION)} · 本报告由 SQL 注入检测引擎自动生成</footer>`;

    return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
      <title>SQL 注入检测报告 ${report.scanId}</title>
      <style>
        body{font-family:system-ui,'Microsoft YaHei',sans-serif;margin:24px;color:#222}
        h1{font-size:20px}h2{font-size:16px;margin-top:24px}
        table{border-collapse:collapse;width:100%;margin-top:8px}
        th,td{border:1px solid #ccc;padding:6px 8px;font-size:13px;text-align:left}
        th{background:#f5f5f5}.critical{color:#c62828;font-weight:bold}
        .high{color:#ef6c00}.medium{color:#f9a825}.low{color:#9e9e9e}
        .meta{color:#666;font-size:13px}pre{background:#f7f7f7;padding:10px;border-radius:6px;white-space:pre-wrap;word-break:break-all}
        .toc{background:#fafafa;border:1px solid #eee;border-radius:6px;padding:10px 14px;margin:12px 0}
        .toc-title{font-weight:600;margin-bottom:4px}
        .toc ul{margin:0;padding-left:18px}.toc a{color:#1565c0;text-decoration:none}.toc a:hover{text-decoration:underline}
        .print-btn{margin:12px 0;padding:8px 14px;background:#1565c0;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:13px}
        .legend{display:flex;gap:10px;flex-wrap:wrap;margin:8px 0 4px}.legend .lg{font-size:12px;padding:2px 10px;border-radius:4px;color:#fff;font-weight:600}.legend .critical{background:#c62828}.legend .high{background:#ef6c00}.legend .medium{background:#f9a825}.legend .low{background:#9e9e9e}
        .rp-footer{margin-top:28px;padding-top:8px;border-top:1px solid #eee;color:#999;font-size:12px}
        @media print{body{margin:12mm;color:#000}.print-btn{display:none}h1,h2{break-after:avoid}tr,li{break-inside:avoid}pre{white-space:pre-wrap;word-break:break-all}a{color:#000;text-decoration:none}}
      </style></head><body>
      <h1>SQL 注入检测报告</h1>
      <p class="meta">扫描ID：${report.scanId} · 风险等级：<b>${report.riskLevel}</b> · 数据库：${report.dbms || '-'}</p>
      <p class="meta">目标：${this._escape(report.target?.baseUrl || '-')} · 注入点：${(report.points || []).length} · 漏洞：${(report.vulns || []).length}</p>
      <button class="print-btn" onclick="window.print()">打印此报告 / 导出 PDF</button>
      ${tocHtml}
      ${legendHtml}
      ${statsHtml}
      ${wafHtml}
      <h2 id="sec-vulns">漏洞清单</h2>
      <table><thead><tr><th>注入点</th><th>技术</th><th>数据库</th><th>风险</th><th>说明</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="5">未发现漏洞</td></tr>'}</tbody></table>
      ${alertsHtml}
      <h2 id="sec-payloads">Payload 示例</h2>
      <pre>${payloads || '无'}</pre>
      ${footerHtml}
      </body></html>`;
  }

  _escape(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }
}

export default ReportGenerator;
