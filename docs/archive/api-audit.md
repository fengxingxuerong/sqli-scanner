# API 审计报告

> 生成日期：2026-01-xx
> 前端 base：`/api`（Web 同源代理）/ `http://127.0.0.1:4567`（Tauri）
> 后端挂载：`/api` + 裸路径（`/`），sqlmap 单独挂载 `/sqlmap`

---

## 前端 → 后端端点映射

| # | 前端调用 | 方法 | 后端路径 | 状态 |
|---|----------|------|----------|------|
| 1 | `apiClient.get('/scan/{id}/report')` | GET | `/api/scan/:id/report` | ✅ |
| 2 | `apiClient.post('/scan/start')` | POST | `/api/scan/start` | ✅ |
| 3 | `apiClient.post('/scan/stop')` | POST | `/api/scan/stop` | ✅ |
| 4 | `apiClient.get('/tampers')` | GET | `/api/tampers` | ✅ |
| 5 | `apiClient.get('/exploit/capabilities')` | GET | `/api/exploit/capabilities` | ✅ |
| 6 | `apiClient.post('/exploit/sql')` | POST | `/api/exploit/sql` | ✅ |
| 7 | `apiClient.post('/exploit/file-read')` | POST | `/api/exploit/file-read` | ✅ |
| 8 | `apiClient.post('/exploit/file-write')` | POST | `/api/exploit/file-write` | ✅ |
| 9 | `apiClient.post('/exploit/os-shell')` | POST | `/api/exploit/os-shell` | ✅ |
| 10 | `sqlmapClient.status()` (GET `/sqlmap/status`) | GET | `/api/sqlmap/status` + `/sqlmap/status` | ✅ |
| 11 | `apiClient.get('/sqlmap/{id}/report')` | GET | `/api/sqlmap/:id/report` + `/sqlmap/:id/report` | ✅ |
| 12 | `fetch('/scan/{id}/report/export?format=...')` | GET | `/api/scan/:id/report/export` | ✅ |

**后端路由挂载（server/index.js）：**
```
app.use('/api', healthRoutes);    // 所有路由挂载在 /api 下
app.use('/api', scanRoutes);
app.use('/api', exploitRoutes);
app.use('/api', tamperRoutes);
app.use('/', healthRoutes);       // 裸路径也挂载（兼容性）
app.use('/', scanRoutes);
app.use('/', exploitRoutes);
app.use('/', tamperRoutes);
app.use('/api/sqlmap', sqlmapRoutes);
app.use('/sqlmap', sqlmapRoutes);
```

---

## 详细路由检查

### scanRoutes.js
- `GET /scan/:id/report` → 返回 `ReportModel`
- `POST /scan/start` → 接收 `{engine, url, method, config, sqlmapConfig, ...}`
- `POST /scan/stop` → 接收 `{scanId}`
- `GET /scan/:id/report/export` → 返回裸内容（html/json/csv/markdown）

### tamperRoutes.js
- `GET /tampers` → 返回 `TamperInfo[]`

### exploitRoutes.js
- `GET /exploit/capabilities` → 返回 `ExploitCapabilities`
- `POST /exploit/sql` → 接收 `{target, point, dbms, sql, ...}`
- `POST /exploit/file-read` → 接收 `{target, point, dbms, path, ...}`
- `POST /exploit/file-write` → 接收 `{target, point, dbms, content, remotePath, ...}`
- `POST /exploit/os-shell` → 接收 `{target, point, dbms, cmd, ...}`

### sqlmapRoutes.js
- `GET /sqlmap/status` → 返回 `{available, script, python, maxConcurrent}`
- `GET /sqlmap/:id/report` → 返回 `Partial<SqlmapReportData>`

### healthRoutes.js
- `GET /health` → 健康检查

---

## 潜在问题

### 1. 响应格式匹配
前端 `apiClient` 期望 `{code: 0, data: T, message: string}` 格式。
需要确认后端所有路由返回的 JSON 结构是否一致。

### 2. Exploit 端点参数结构
前端 `exploitClient` 发送的 payload 结构：
```ts
{
  target: { url, method, bodyParams, cookieParams, headerParams },
  point: { originalValue },
  dbms,
  authorized,
  ...extraParams  // sql, path, content, cmd 等
}
```
需要确认后端 exploitRoutes 路由解析的字段名一致。

### 3. 导出端点
前端 `exportReport` 使用 `fetch()` 直接请求 `/scan/:id/report/export`
而非 `apiClient.get`，因为期望返回裸内容而非 `{code,data,message}` 包装。
后端需要确认该端点返回裸内容。

---

## 结论

所有 12 个前端 API 调用在**后端都有对应的路由实现**。
无明显的 endpoint mismatch 问题。
建议在启动前后端后运行一次端到端测试验证实际响应格式。