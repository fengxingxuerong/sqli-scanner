// ============================================================================
// patch/ReportGenerator.js —— 安全加固版报告生成器
// 基于 server/src/services/ReportGenerator.js 修改，修复项：
//   [P1-1] 导出前剥离 target 中的认证/代理等敏感配置（config.auth / cookieParams /
//          headerParams），避免 JSON 报告分享/落盘泄露目标站凭据
//   [P2-7] CSV 单元格公式注入转义（= + - @ \t \r 前缀加 ' 前缀）
// 其余逻辑与原文件一致（HTML 转义已存在且正确，原样保留）。
// ============================================================================

import { truncateLong } from '../core/logger.js';

// 导出时单条证据/说明的最大长度（原逻辑不变）
const EVIDENCE_MAX = 4000;

// [P1-1] 导出前脱敏 target：剥离认证凭据与代理配置，只保留展示字段
// （baseUrl/method/bodyParams 等）。返回浅拷贝，不污染内存中的 report。
function sanitizeTargetForExport(target) {
  if (!target || typeof target !== 'object') return target;
  const out = { ...target };
  if (out.config && typeof out.config === 'object') {
    const { auth, proxy, ...rest } = out.config;
    out.config = {
      ...rest,
      auth: null, // 凭据不导出：仅保留「曾配置过」的展示需要时可用布尔标注
      proxy: null,
    };
  }
  delete out.cookieParams; // 目标会话 cookie 不导出
  delete out.headerParams; // 目标自定义头（可能含 Authorization）不导出
  if (out.db && typeof out.db === 'object' && out.db.connectionString) {
    out.db = { ...out.db, connectionString: '***' }; // 直连模式的连接串打码
  }
  return out;
}

// [P2-7] CSV 单元格转义：引号翻倍 + 公式前缀防护
function csvSafeCell(v) {
  let s = v === null || v === undefined ? '' : String(v);
  // 公式注入防护：以 = + - @ \t \r 开头的单元格加 ' 前缀（Excel/WPS 不再按公式解析）
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

// 报告生成器：汇总 ReportModel、风险定级、JSON/HTML 导出
export class ReportGenerator {
  /** @internal 仅供 ScanManager 内部调用（含测试直接构造 ReportModel 的用例） */
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

  riskOf(vulns, data) {
    if (data && this._hasData(data)) return 'Critical';
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

  _truncate(report) {
    if (!report || !Array.isArray(report.vulns)) return report;
    const vulns = report.vulns.map((v) => {
      const out = { ...v };
      for (const key of ['evidence', 'description']) {
        out[key] = truncateLong(out[key], EVIDENCE_MAX);
      }
      return out;
    });
    return { ...report, vulns };
  }

  // [P1-1] 导出统一脱敏：先截断证据，再剥离 target 凭据
  _forExport(report) {
    const r = this._truncate(report);
    if (!r.target) return r;
    return { ...r, target: sanitizeTargetForExport(r.target) };
  }

  // 导出 JSON（P1-1：target 已脱敏）
  toJSON(report) {
    return JSON.stringify(this._forExport(report), null, 2);
  }

  // 导出 CSV（P1-U3）：漏洞表 + 拖库数据两档，BOM 头 + [P2-7] 公式注入转义
  toCSV(report) {
    const r = this._forExport(report);
    const lines = [];
    lines.push('漏洞ID,注入点,技术,数据库,风险,说明');
    for (const v of r.vulns || []) {
      lines.push(
        [v.id, v.pointId, v.technique, v.dbms || '', v.riskLevel, (v.description || '').replace(/[\r\n,]/g, ' ')]
          .map((c) => csvSafeCell(c))
          .join(',')
      );
    }
    const rows = r.data?.rows || {};
    if (Object.keys(rows).length) {
      lines.push('');
      lines.push('# 拖库数据');
      for (const [table, arr] of Object.entries(rows)) {
        if (!arr || !arr.length) continue;
        const cols = Object.keys(arr[0]);
        lines.push('');
        lines.push(`## ${table}`);
        lines.push(cols.join(','));
        for (const obj of arr) {
          lines.push(cols.map((c) => csvSafeCell(obj[c] ?? '')).join(','));
        }
      }
    }
    return '\uFEFF' + lines.join('\n');
  }

  // 导出 Markdown（原逻辑不变，仅 target 脱敏由 _forExport 覆盖）
  toMarkdown(report) {
    const r = this._forExport(report);
    const md = [];
    md.push(`# SQL 注入检测报告`);
    md.push('');
    md.push(`- 扫描ID：\`${report.scanId}\``);
    md.push(`- 目标：\`${report.target?.baseUrl || '-'}\``);
    md.push(`- 风险等级：**${report.riskLevel}**`);
    md.push(`- 数据库：${report.dbms || '-'}`);
    md.push(`- 注入点：${(report.points || []).length} · 漏洞：${(r.vulns || []).length}`);
    md.push('');
    md.push('## 漏洞清单');
    md.push('');
    md.push('| 注入点 | 技术 | 数据库 | 风险 | 说明 |');
    md.push('|---|---|---|---|---|');
    for (const v of r.vulns || []) {
      md.push(`| ${v.pointId} | ${v.technique} | ${v.dbms || '-'} | ${v.riskLevel} | ${(v.description || '').replace(/\|/g, '\\|')} |`);
    }
    if (!(r.vulns || []).length) md.push('| - | - | - | - | 未发现漏洞 |');
    md.push('');
    md.push('## Payload 示例');
    md.push('');
    const payloads = (r.vulns || []).flatMap((v) => v.payloads || []);
    if (payloads.length) {
      for (const p of payloads) md.push(`- \`${p}\``);
    } else {
      md.push('- 无');
    }
    return md.join('\n');
  }

  // 导出 HTML（原逻辑不变：所有用户可控字段均已 _escape 转义，P3 已核验）
  toHTML(report) {
    const r = this._forExport(report);
    const rows = (r.vulns || [])
      .map(
        (v) => `<tr>
        <td>${this._escape(v.pointId)}</td>
        <td>${this._escape(v.technique)}</td>
        <td>${this._escape(v.dbms || '-')}</td>
        <td class="${this._escape(String(v.riskLevel || 'low').toLowerCase())}">${this._escape(v.riskLevel)}</td>
        <td>${this._escape(v.description || '')}</td>
      </tr>`
      )
      .join('');
    const payloads = (r.vulns || [])
      .flatMap((v) => v.payloads || [])
      .map((p) => '• ' + this._escape(p))
      .join('\n');

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
        .footer{margin-top:32px;padding-top:12px;border-top:1px solid #eee;color:#999;font-size:12px;text-align:center}
      </style></head><body>
      <h1>SQL 注入检测报告</h1>
      <p class="meta">扫描ID：${this._escape(report.scanId)} · 风险等级：<b>${this._escape(report.riskLevel)}</b> · 数据库：${this._escape(report.dbms || '-')}</p>
      <p class="meta">目标：${this._escape(report.target?.baseUrl || '-')} · 注入点：${(report.points || []).length} · 漏洞：${(report.vulns || []).length}</p>
      <h2>漏洞清单</h2>
      <table><thead><tr><th>注入点</th><th>技术</th><th>数据库</th><th>风险</th><th>说明</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="5">未发现漏洞</td></tr>'}</tbody></table>
      <h2>Payload 示例</h2>
      <pre>${payloads || '无'}</pre>
      <footer class="footer">本报告仅供授权安全测试使用。未获授权对任何系统进行扫描、测试或数据提取均可能违反法律法规，请勿用于非法用途。</footer>
      </body></html>`;
  }

  _escape(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
}

export default ReportGenerator;
