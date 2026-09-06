// one-click-scan.mjs — 一键扫描 + AI 漏洞报告
const BASE = 'http://127.0.0.1:4567';
const TARGET = process.argv[2] || 'http://127.0.0.1:8130/Less-1/?id=1';

async function main() {
  console.log('═══════════════════════════════════════════');
  console.log('  一键 SQL 注入扫描 + AI 漏洞报告');
  console.log('═══════════════════════════════════════════\n');
  console.log(`目标: ${TARGET}\n`);

  // 1. 启动扫描
  console.log('[1/4] 启动扫描...');
  const startRes = await fetch(`${BASE}/api/scan/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: TARGET,
      method: 'GET',
      config: {
        techniques: ['union', 'error', 'boolean', 'time', 'stacked', 'inline'],
        enableExtract: true,
        concurrency: 4,
        ratePerSec: 0,
        level: 3,
        risk: 2,
      },
    }),
  }).then(r => r.json());

  if (startRes.code !== 0) {
    console.log('启动失败:', startRes.message);
    return;
  }
  const scanId = startRes.data.scanId;
  console.log(`  scanId: ${scanId}`);

  // 2. 轮询等待完成
  console.log('[2/4] 扫描中...');
  const deadline = Date.now() + 120000;
  let report = null;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 500));
    const r = await fetch(`${BASE}/api/scan/${scanId}/report`).then(r => r.json());
    if (r.code === 0 && r.data && r.data.finishedAt) {
      report = r.data;
      break;
    }
  }

  if (!report) {
    console.log('  扫描超时');
    return;
  }

  console.log(`  状态: ${report.riskLevel}`);
  console.log(`  漏洞数: ${report.vulns?.length || 0}`);
  console.log(`  数据库: ${report.dbms || '未识别'}`);

  if (report.vulns?.length > 0) {
    console.log('\n  检出漏洞:');
    for (const v of report.vulns) {
      console.log(`    [${v.riskLevel}] ${v.technique} @ ${v.pointId}`);
      console.log(`      ${v.evidence?.slice(0, 80) || ''}`);
    }
  }

  if (report.data) {
    console.log('\n  提取数据:');
    if (report.data.databases?.length) console.log(`    数据库: ${report.data.databases.join(', ')}`);
    if (report.data.currentDb) console.log(`    当前库: ${report.data.currentDb}`);
    if (report.data.currentUser) console.log(`    当前用户: ${report.data.currentUser}`);
    const tableCount = Object.keys(report.data.tables || {}).length;
    if (tableCount) console.log(`    表数: ${tableCount}`);
    const rowCount = Object.values(report.data.rows || {}).filter(r => Array.isArray(r) && r.length).length;
    if (rowCount) console.log(`    有数据的表: ${rowCount}`);
  }

  // 3. AI 漏洞报告
  console.log('\n[3/4] 生成 AI 漏洞报告...');
  console.log('  (3 模型流水线: analyst→writer→reviewer，约 60-120s)');
  try {
    const aiRes = await fetch(`${BASE}/api/scan/${scanId}/report/ai`, {
      method: 'POST',
      timeout: 180000,
    }).then(r => r.json());

    if (aiRes.code === 0 && aiRes.data) {
      console.log(`  模型: ${aiRes.data.model || 'unknown'}`);
      console.log(`  审阅: ${aiRes.data.reviewNote || '无'}`);
      console.log(`  缓存: ${aiRes.data.cached ? '是' : '否'}`);
      console.log('\n═══════════════════════════════════════════');
      console.log('  AI 漏洞报告');
      console.log('═══════════════════════════════════════════\n');
      console.log(aiRes.data.content || '(无内容)');
    } else {
      console.log(`  AI 报告失败: ${aiRes.message || JSON.stringify(aiRes)}`);
    }
  } catch (e) {
    console.log(`  AI 报告异常: ${e.message}`);
  }

  console.log('\n[4/4] 完成');
  console.log(`  扫描 ID: ${scanId}`);
  console.log(`  Web UI: http://127.0.0.1:4567/report/${scanId}`);
}

main().catch(e => { console.error('FATAL:', e); process.exit(1); });