// ============================================================================
// e2e/oob-real-lab/mysql-lab-app.mjs —— MySQL 版无回显 OOB 靶场（真实 MySQL 8.0.28 @3307）
// 与 lab-app.mjs（PG 版）同构：无回显 + WAF（拦 sleep/报错/union）+ 字符串上下文注入点
// 差异：mysql2 驱动 + Pool（3307 root/root sqli_lab，users 表 name 列）
// ============================================================================
import { createRequire } from 'node:module';
const _require = createRequire(new URL('../../server/package.json', import.meta.url));
const express = _require('express');
const mysql2 = _require('mysql2/promise');

const MYSQL_CONF = { host: '127.0.0.1', port: 3307, user: 'root', password: 'root', database: 'sqli_lab' };

export function createMysqlOobLabApp({ waf = true } = {}) {
  const pool = mysql2.createPool({ ...MYSQL_CONF, connectionLimit: 8, multipleStatements: true });
  const app = express();
  app.use(express.urlencoded({ extended: true }));

  if (waf) {
    const BLOCK_RE = /sleep\s*\(|benchmark\s*\(|waitfor|extractvalue|updatexml|union\s+select/i;
    app.use((req, res, next) => {
      const vals = Object.values(req.query).join(' ') + ' ' + Object.values(req.body || {}).join(' ');
      if (BLOCK_RE.test(vals)) {
        res.status(403).send('<!DOCTYPE html><html><body><h1>403</h1><p>Request blocked by lab WAF</p></body></html>');
        return;
      }
      next();
    });
  }

  // 无回显注入点（字符串上下文，匹配 MySQL OOB 模板 {ORIG}' AND LOAD_FILE(...) 的引号闭合）
  // [诊断] 记录实际到达的注入值与 SQL 报错（DNS OOB 引擎级排障用）
  app.get('/oob', async (req, res) => {
    const name = req.query.name || 'user1';
    console.log(`[lab] /oob name=${JSON.stringify(String(name).slice(0, 140))}`);
    try {
      const sql = `SELECT * FROM users WHERE username = '${name}'`;
      await pool.query(sql);
      res.send('<!DOCTYPE html><html><head><title>Done</title></head><body><p>request processed</p></body></html>');
    } catch (e) {
      console.log(`[lab] SQL错误: ${String(e.message).slice(0, 160)}`);
      res.send('<!DOCTYPE html><html><head><title>Done</title></head><body><p>request processed</p></body></html>');
    }
  });

  return { app, close: async () => { await pool.end().catch(() => {}); } };
}
