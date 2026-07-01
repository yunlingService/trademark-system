#!/usr/bin/env python3
"""
商标管理系统后端 - 纯 Python 标准库，零依赖
数据库：SQLite (trademark.db)
"""

import http.server
import os
import json
import sqlite3
import hashlib
import secrets
import time
import urllib.parse
from datetime import datetime

DB = os.path.join(os.path.dirname(__file__), 'trademark.db')
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', '8765'))  # Railway 会设置 PORT 环境变量
TOKEN_TIMEOUT = 7200  # 2小时

# ===== 数据库初始化 =====
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS submissions (
        id TEXT PRIMARY KEY,
        data TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS admin_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS tokens (
        token TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        created_at REAL NOT NULL
    )''')
    # 默认管理员账号
    row = c.execute("SELECT value FROM admin_config WHERE key='admin'").fetchone()
    if not row:
        default_hash = hashlib.sha256(('admin' + 'admin123').encode()).hexdigest()
        c.execute("INSERT INTO admin_config (key, value) VALUES (?, ?)",
                  ('admin', json.dumps({'username': 'admin', 'password_hash': default_hash}, ensure_ascii=False)))
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def verify_token(token):
    if not token:
        return None
    conn = get_db()
    row = conn.execute("SELECT * FROM tokens WHERE token=?", (token,)).fetchone()
    conn.close()
    if row and time.time() - row['created_at'] < TOKEN_TIMEOUT:
        return row['username']
    return None

def json_response(data, status=200):
    data_bytes = json.dumps(data, ensure_ascii=False).encode('utf-8')
    return (status, {'Content-Type': 'application/json; charset=utf-8'}, data_bytes)

def read_body(handler):
    length = int(handler.headers.get('Content-Length', 0))
    if length == 0:
        return {}
    body = handler.rfile.read(length)
    return json.loads(body.decode('utf-8'))

class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')

        # API 路由
        if path == '/api/site-content':
            conn = get_db()
            row = conn.execute("SELECT value FROM admin_config WHERE key='site_content'").fetchone()
            conn.close()
            content = json.loads(row['value']) if row else {}
            self._send_json({'ok': True, 'content': content})
            return

        if path == '/api/submissions':
            token = self.headers.get('X-Token', '')
            user = verify_token(token)
            if not user:
                self._send_json({'ok': False, 'error': '未登录'}, 401)
                return
            conn = get_db()
            rows = conn.execute("SELECT data FROM submissions ORDER BY created_at DESC").fetchall()
            conn.close()
            submissions = [json.loads(r['data']) for r in rows]
            self._send_json({'ok': True, 'submissions': submissions})
            return

        if path == '/api/admin/config':
            token = self.headers.get('X-Token', '')
            user = verify_token(token)
            if not user:
                self._send_json({'ok': False, 'error': '未登录'}, 401)
                return
            conn = get_db()
            row = conn.execute("SELECT value FROM admin_config WHERE key='admin'").fetchone()
            conn.close()
            config = json.loads(row['value'])
            self._send_json({'ok': True, 'username': config['username']})
            return

        # 静态文件（默认行为）
        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')

        if path == '/api/login':
            data = read_body(self)
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()
            pw_hash = hashlib.sha256((username + password).encode()).hexdigest()
            conn = get_db()
            row = conn.execute("SELECT value FROM admin_config WHERE key='admin'").fetchone()
            conn.close()
            if not row:
                self._send_json({'ok': False, 'error': '管理员未配置'}, 401)
                return
            config = json.loads(row['value'])
            if config['username'] == username and config['password_hash'] == pw_hash:
                token = secrets.token_hex(32)
                conn = get_db()
                conn.execute("INSERT INTO tokens (token, username, created_at) VALUES (?, ?, ?)",
                             (token, username, time.time()))
                conn.commit()
                conn.close()
                self._send_json({'ok': True, 'token': token, 'username': username})
            else:
                self._send_json({'ok': False, 'error': '账号或密码错误'}, 401)
            return

        if path == '/api/submissions':
            data = read_body(self)
            submission = data.get('submission', {})
            if not submission.get('id'):
                self._send_json({'ok': False, 'error': '缺少 submission.id'}, 400)
                return
            # 去掉 files 中的 dataUrl
            if 'files' in submission:
                slim_files = []
                for f in submission['files']:
                    slim_files.append({'name': f.get('name'), 'size': f.get('size'), 'category': f.get('category')})
                submission['files'] = slim_files
            now = datetime.now().isoformat()
            conn = get_db()
            conn.execute("INSERT OR REPLACE INTO submissions (id, data, created_at) VALUES (?, ?, ?)",
                         (submission['id'], json.dumps(submission, ensure_ascii=False), now))
            conn.commit()
            conn.close()
            self._send_json({'ok': True, 'id': submission['id']})
            return

        if path == '/api/site-content':
            token = self.headers.get('X-Token', '')
            user = verify_token(token)
            if not user:
                self._send_json({'ok': False, 'error': '未登录'}, 401)
                return
            data = read_body(self)
            content = data.get('content', {})
            conn = get_db()
            conn.execute("INSERT OR REPLACE INTO admin_config (key, value) VALUES (?, ?)",
                         ('site_content', json.dumps(content, ensure_ascii=False)))
            conn.commit()
            conn.close()
            self._send_json({'ok': True})
            return

        if path == '/api/admin/config':
            token = self.headers.get('X-Token', '')
            user = verify_token(token)
            if not user:
                self._send_json({'ok': False, 'error': '未登录'}, 401)
                return
            data = read_body(self)
            username = data.get('username', '').strip()
            password = data.get('password', '')
            if not username or not password:
                self._send_json({'ok': False, 'error': '用户名和密码不能为空'}, 400)
                return
            pw_hash = hashlib.sha256((username + password).encode()).hexdigest()
            conn = get_db()
            conn.execute("UPDATE admin_config SET value=? WHERE key='admin'",
                         (json.dumps({'username': username, 'password_hash': pw_hash}, ensure_ascii=False),))
            conn.commit()
            conn.close()
            self._send_json({'ok': True})
            return

        self._send_json({'ok': False, 'error': 'Not Found'}, 404)

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')

        # PUT /api/submissions/<id>/status
        if '/api/submissions/' in path and path.endswith('/status'):
            parts = path.split('/')
            if len(parts) >= 4:
                submission_id = parts[3]
                token = self.headers.get('X-Token', '')
                user = verify_token(token)
                if not user:
                    self._send_json({'ok': False, 'error': '未登录'}, 401)
                    return
                data = read_body(self)
                status = data.get('status', '')
                notes = data.get('notes', '')
                conn = get_db()
                row = conn.execute("SELECT data FROM submissions WHERE id=?", (submission_id,)).fetchone()
                if not row:
                    conn.close()
                    self._send_json({'ok': False, 'error': '未找到'}, 404)
                    return
                sub = json.loads(row['data'])
                sub['status'] = status
                sub['notes'] = notes
                conn.execute("UPDATE submissions SET data=? WHERE id=?",
                             (json.dumps(sub, ensure_ascii=False), submission_id))
                conn.commit()
                conn.close()
                self._send_json({'ok': True})
                return

        self._send_json({'ok': False, 'error': 'Not Found'}, 404)

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')

        if '/api/submissions/' in path:
            parts = path.split('/')
            if len(parts) >= 4:
                submission_id = parts[3]
                token = self.headers.get('X-Token', '')
                user = verify_token(token)
                if not user:
                    self._send_json({'ok': False, 'error': '未登录'}, 401)
                    return
                conn = get_db()
                conn.execute("DELETE FROM submissions WHERE id=?", (submission_id,))
                conn.commit()
                conn.close()
                self._send_json({'ok': True})
                return

        self._send_json({'ok': False, 'error': 'Not Found'}, 404)

    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Token')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Token')
        self.send_header('Content-Length', '0')
        self.end_headers()

if __name__ == '__main__':
    init_db()
    server = http.server.HTTPServer((HOST, PORT), RequestHandler)
    print(f'🚀 商标管理系统后端已启动: http://localhost:{PORT}')
    print(f'   管理员登录: http://localhost:{PORT}/admin.html')
    print(f'   静态文件 + API（零依赖，纯 Python 标准库）')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n服务已停止')
        server.server_close()
