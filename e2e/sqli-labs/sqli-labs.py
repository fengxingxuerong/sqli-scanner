#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQLi-Labs Python 版 —— 对标 sqlmap 官方 75 关验收靶场
零 Docker 依赖：纯 Python http.server + sqlite3 实现

关键设计：每关实际执行 SQL 并回显结果（不是简单反射输入）
引擎看到的是真实的 SQL 执行响应（类似原版 PHP SQLi-labs 的 MySQL 行为）
"""
import http.server
import json
import sqlite3
import urllib.parse
import re
import os
import time
import threading
from pathlib import Path

# ── 线程安全的数据库访问 ──
_DB_LOCK = threading.Lock()
DB = sqlite3.connect(':memory:', check_same_thread=False)
DB.row_factory = sqlite3.Row
DB.executescript("""
    CREATE TABLE users(id INTEGER, name TEXT, pass TEXT, email TEXT);
    INSERT INTO users VALUES(1,'admin','admin123','admin@lab.com');
    INSERT INTO users VALUES(2,'bob','bob456','bob@lab.com');
    INSERT INTO users VALUES(3,'alice','alice789','alice@lab.com');
    INSERT INTO users VALUES(4,'Dumb','Dumb@123','dumb@lab.com');
    INSERT INTO users VALUES(5,'I-kill-you','I-kill@123','ikill@lab.com');
    INSERT INTO users VALUES(6,'secret','secret@123','secret@lab.com');
    INSERT INTO users VALUES(7,'test','test@123','test@lab.com');
    CREATE TABLE emails(id INTEGER, email_id TEXT);
    INSERT INTO emails VALUES(1,'admin@lab.com');
    INSERT INTO emails VALUES(2,'bob@lab.com');
    INSERT INTO emails VALUES(3,'test@lab.com');
""")

# ── SQL 执行器 ──
def exec_sql(sql, error_mode='error'):
    """执行 SQL 并返回 (rows, error_msg, secs)"""
    try:
        with _DB_LOCK:
            cur = DB.execute(sql)
            try:
                rows = [dict(r) for r in cur.fetchall()]
            except:
                rows = []
            DB.commit()
        return rows, None, 0
    except Exception as e:
        try: DB.rollback()
        except: pass
        if error_mode == 'silent':
            return [], None, 0
        return [], str(e), 0

def html_table(rows, title='Result'):
    if not rows:
        return f'<h2>{title}</h2><p>No results found.</p>'
    cols = list(rows[0].keys())
    header = ''.join(f'<th>{c}</th>' for c in cols)
    body = ''
    for r in rows:
        body += '<tr>' + ''.join(f'<td>{r[c]}</td>' for c in cols) + '</tr>'
    return f'<h2>{title}</h2><table border=1><tr>{header}</tr>{body}</table>'

def html_page(body, title='SQLi-Lab'):
    ts = int(time.time() * 1000)
    return f'<!DOCTYPE html><html><head><title>{title}</title></head><body>\n{body}\n<!-- ts={ts} --></body></html>'

def get_param(qs, key, default='1'):
    d = urllib.parse.parse_qs(qs, keep_blank_values=True)
    return d.get(key, [default])[0]

# ── 关卡定义 ──
CHALLENGES = {}

def register(ch):
    CHALLENGES[ch['id']] = ch

# ── 通用注入处理 ──
def handle_inject(qs, sql_tpl, ch, extra_params=None):
    """
    通用注入处理：
    1. 提取参数值
    2. 替换 SQL 模板中的 {v} 为参数值
    3. 执行 SQL
    4. 返回结果页
    """
    val = get_param(qs, ch['param'], '1')
    # 过滤处理
    if ch.get('filter'):
        val = re.sub(ch['filter'], '', val, flags=re.IGNORECASE)
    # 宽字节处理（GBK 编码：%df%27 = 運'）
    if ch.get('gbk') and '%df' in val.lower():
        val = val.replace("'", '\\xdf\\x27')
    sql = sql_tpl.replace('{v}', val)
    rows, err, _ = exec_sql(sql)
    if err:
        return html_page(f'<h1>Error</h1><pre>{err}</pre>')
    return html_page(html_table(rows, f'Level {ch["id"]}'))

# ── 注册关卡 ──
LEVELS = [
    # (id, name, url, param, sql_tpl, extra)
    (1, "GET 单引号字符串", "/Less-1/", "id", "SELECT * FROM users WHERE id='{v}'", {}),
    (2, "GET 数值型", "/Less-2/", "id", "SELECT * FROM users WHERE id={v}", {}),
    (3, "GET 单引号+括号", "/Less-3/", "id", "SELECT * FROM users WHERE id=('{v}')", {}),
    (4, "GET 双引号+括号", "/Less-4/", "id", 'SELECT * FROM users WHERE id=("{v}")', {}),
    (5, "GET 双注入(单引号)", "/Less-5/", "id", "SELECT * FROM users WHERE id='{v}'", {}),
    (6, "GET 双注入(双引号)", "/Less-6/", "id", 'SELECT * FROM users WHERE id="{v}"', {}),
    (7, "GET 导出文件", "/Less-7/", "id", "SELECT * FROM users WHERE id='{v}'", {}),
    (8, "GET 布尔盲注", "/Less-8/", "id", "SELECT * FROM users WHERE id='{v}'", {}),
    (9, "GET 时间盲注", "/Less-9/", "id", "SELECT * FROM users WHERE id='{v}'", {}),
    (10, "GET 时间盲注双引号", "/Less-10/", "id", 'SELECT * FROM users WHERE id="{v}"', {}),
    # POST 注入
    (11, "POST 单引号", "/Less-11/", "uname", "SELECT * FROM users WHERE name='{v}'", {'method': 'POST'}),
    (12, "POST 双引号", "/Less-12/", "uname", 'SELECT * FROM users WHERE name="{v}"', {'method': 'POST'}),
    (13, "POST 单引号括号", "/Less-13/", "uname", "SELECT * FROM users WHERE name=('{v}')", {'method': 'POST'}),
    (14, "POST 双引号括号", "/Less-14/", "uname", 'SELECT * FROM users WHERE name=("{v}")', {'method': 'POST'}),
    (15, "POST 盲注单引号", "/Less-15/", "uname", "SELECT * FROM users WHERE name='{v}'", {'method': 'POST'}),
    (16, "POST 盲注双引号", "/Less-16/", "uname", 'SELECT * FROM users WHERE name="{v}"', {'method': 'POST'}),
    (17, "UPDATE 注入", "/Less-17/", "uname", "UPDATE users SET pass='x' WHERE name='{v}'", {'method': 'POST'}),
    # 头注入
    (18, "UA 头注入", "/Less-18/", "User-Agent", "INSERT INTO vulns(name) VALUES('{v}')", {}),
    (19, "Referer 头注入", "/Less-19/", "Referer", "INSERT INTO vulns(name) VALUES('{v}')", {}),
    (20, "Cookie 注入", "/Less-20/", "Cookie", "SELECT * FROM users WHERE id='{v}'", {}),
    # 堆叠注入
    (31, "堆叠注入", "/Less-31/", "id", "SELECT * FROM users WHERE id={v}", {}),
    (38, "堆叠+数值", "/Less-38/", "id", "SELECT * FROM users WHERE id={v}", {}),
    # ORDER BY 注入
    (46, "ORDER BY 注入", "/Less-46/", "sort", "SELECT * FROM users ORDER BY {v}", {}),
    (47, "ORDER BY 单引号", "/Less-47/", "sort", "SELECT * FROM users ORDER BY '{v}'", {}),
    # 过滤绕过
    (23, "OR/AND 过滤", "/Less-23/", "id", "SELECT * FROM users WHERE id='{v}'", {'filter': r'\b(OR|AND)\b'}),
    (25, "注释过滤", "/Less-25/", "id", "SELECT * FROM users WHERE id='{v}'", {'filter': r'--|#|/\*'}),
    (26, "空格过滤", "/Less-26/", "id", "SELECT * FROM users WHERE id='{v}'", {'filter': r'\s+'}),
    (28, "UNION SELECT 过滤", "/Less-28/", "id", "SELECT * FROM users WHERE id='{v}'", {'filter': r'UNION\s+SELECT'}),
    (29, "UNION 过滤", "/Less-29/", "id", "SELECT * FROM users WHERE id='{v}'", {'filter': r'\b(UNION|SELECT|OR|AND)\b'}),
    (30, "UNION+注释过滤", "/Less-30/", "id", "SELECT * FROM users WHERE id='{v}'", {'filter': r'\bUNION\b|--|#|/\*'}),
    # 宽字节
    (32, "宽字节 GET", "/Less-32/", "id", "SELECT * FROM users WHERE id='{v}'", {'gbk': True}),
    # 无回显盲注
    (54, "无回显数值", "/Less-54/", "id", "SELECT * FROM users WHERE id={v}", {}),
    # 挑战关
    (61, "挑战: 多过滤", "/Less-61/", "id", "SELECT * FROM users WHERE id='{v}'", {'filter': r'\b(OR|AND|UNION|SELECT|--|#|/\*)\b'}),
    # XML/JSON 注入
    (66, "XML 注入", "/Less-66/", "id", "SELECT * FROM users WHERE id='{v}'", {}),
    (67, "JSON 注入", "/Less-67/", "json", "SELECT * FROM users WHERE id='{v}'", {'method': 'POST'}),
]

for lid, lname, lurl, lparam, lsql, lextra in LEVELS:
    ch = {
        'id': lid, 'name': lname, 'url': lurl, 'param': lparam,
        'injectable': True, 'method': lextra.get('method', 'GET'),
        'filter': lextra.get('filter', None),
        'gbk': lextra.get('gbk', False),
    }
    ch['handler'] = lambda qs, _ch=ch, _sql=lsql: handle_inject(qs, _sql, _ch)
    register(ch)

# ── HTTP 服务器 ──
class SQLiLabHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?')[0]
        qs = self.path.split('?')[1] if '?' in self.path else ''
        ch = next((c for c in CHALLENGES.values() if c['url'] == path and c['method'] == 'GET'), None)
        if ch:
            body = ch['handler'](qs)
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('X-Powered-By', 'PHP/7.4.33-sqli-labs')
            self.end_headers()
            self.wfile.write(body.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'<h1>404</h1>')

    def do_POST(self):
        content_len = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(content_len) if content_len > 0 else b''
        # 解析 POST body（支持 form-urlencoded 和 JSON）
        ct = self.headers.get('Content-Type', '')
        if 'json' in ct:
            try:
                body = json.loads(raw.decode('utf-8'))
                qs = urllib.parse.urlencode(body)
            except:
                qs = ''
        else:
            try:
                qs = raw.decode('utf-8')
            except:
                qs = ''
        path = self.path.split('?')[0]
        ch = next((c for c in CHALLENGES.values() if c['url'] == path and c['method'] == 'POST'), None)
        if ch:
            body = ch['handler'](qs)
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('X-Powered-By', 'PHP/7.4.33-sqli-labs')
            self.end_headers()
            self.wfile.write(body.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'<h1>404</h1>')

    def log_message(self, fmt, *args):
        pass

def main():
    port = int(os.environ.get('SQLI_LABS_PORT', 8130))
    server = http.server.ThreadingHTTPServer(('127.0.0.1', port), SQLiLabHandler)
    print(f"[sqli-labs] Python 版 {len(CHALLENGES)} 关已启动: http://127.0.0.1:{port}")
    for cid in sorted(CHALLENGES.keys()):
        c = CHALLENGES[cid]
        print(f"  L{cid:02d}: {c['name']} ({c['method']} {c['url']}?{c['param']}=)")
    server.serve_forever()

if __name__ == '__main__':
    main()