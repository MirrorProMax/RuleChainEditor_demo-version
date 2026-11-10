#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""短路表编辑器本地服务器（替代 python3 -m http.server）

= 静态文件托管 + 三项编辑器专属 API：
  GET  /__editor_stat            → 能力探测：{"ok":true,"server":"editor-save"}（编辑器据此启用服务器写回）
  GET  /__editor_stat?path=X     → 磁盘版本：{"ok":true,"mtime":<毫秒>,"size":<字节>}（乐观锁用）
  POST /__editor_save            → 写回 JSON，覆盖前自动在目标 JSON 同目录创建「备份」文件夹并留副本

设计要点（与编辑器端 #2010 乐观锁 / 覆盖前备份对齐）：
  · 写回范围：请求路径必须落在本服务器启动目录（ROOT）子树内（normpath 削平「..」），
    且请求路径与真实目标（跟随符号链接后）都必须是 .json；ROOT 内软链可指向外部真实文件
    （如 main-config.json → 实例项目配置），写回与备份都落在真实文件处。
  · 乐观锁：客户端带上「上次已知版本」(client_mtime/client_size)；与磁盘当前版本不一致
    （mtime 容差 2000ms，size 严格相等）→ 409，绝不静默覆盖外部改动。
  · 覆盖前备份：备份内容 = 磁盘上即将被覆盖的旧内容（原字节复制）；目录不存在当场创建；
    文件名 = 原名_YYYYMMDD_HHMMSS.json，同一秒多次 → 追加 _2/_3…，绝不覆盖上一份备份。
  · 仅绑定 127.0.0.1，不对外网开放；每次写盘在 stdout 留痕。

用法：python3 server.py [端口]        （默认 8000；在哪个目录启动，哪个目录就是可写 ROOT。
      若配置源在相邻目录（如 dir:../config），请在两层目录的共同父目录启动本服务器。）
"""
import json
import os
import posixpath
import sys
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, unquote

ROOT = os.getcwd()                       # 可写范围 = 启动目录（realpath 后比对）
MAX_BODY = 32 * 1024 * 1024              # 32MB，防异常请求撑爆内存
MTIME_TOL_MS = 2000                      # 与编辑器端 diskStale 的容差一致
BACKUP_DIR_NAME = "备份"


def stat_ms(path):
    """文件当前版本：mtime 毫秒 + size 字节。不存在 → None"""
    try:
        st = os.stat(path)
        return {"mtime": int(st.st_mtime * 1000), "size": st.st_size}
    except OSError:
        return None


def resolve_under_root(rel):
    """把相对路径安全解析为真实绝对路径。返回 realpath 后的绝对路径；越界/非法 → None
    · 请求路径先 normpath 削平（任何「..」都被拦在 ROOT 内），再 realpath 跟随符号链接：
      允许 ROOT 内的软链指向外部真实文件（如 main-config.json → 实例项目配置）——
      写回落在真实文件处，覆盖前备份也建在真实文件同目录（符合「备份在目标 JSON 同路径下」）。
    · 只允许 .json（请求路径与真实目标都须是 .json）。"""
    rel = (rel or "").strip()
    if not rel or "\x00" in rel:
        return None
    # 显式拒绝任何「..」成分（不静默削平，语义更清晰：请求路径必须直接落在 ROOT 内）
    if any(part == ".." for part in rel.replace("\\", "/").split("/")):
        return None
    p = posixpath.normpath("/" + rel.replace("\\", "/")).lstrip("/")
    if not p or not p.lower().endswith(".json"):
        return None
    real = os.path.realpath(os.path.join(ROOT, p))
    if not real.lower().endswith(".json"):       # 真实目标也必须是 .json（软链指向别的类型一律拒绝）
        return None
    return real


def backup_copy(src_path):
    """覆盖前备份：把磁盘旧文件原字节复制到同目录「备份」文件夹。返回备份文件名；无旧文件 → ""；失败抛异常"""
    if not os.path.exists(src_path):
        return ""
    bdir = os.path.join(os.path.dirname(src_path), BACKUP_DIR_NAME)
    os.makedirs(bdir, exist_ok=True)
    base = os.path.splitext(os.path.basename(src_path))[0]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"{base}_{ts}.json"
    n = 2
    while os.path.exists(os.path.join(bdir, name)):   # 同秒多次 → _2/_3…，绝不覆盖上一份
        name = f"{base}_{ts}_{n}.json"
        n += 1
    with open(src_path, "rb") as fr:
        data = fr.read()
    with open(os.path.join(bdir, name), "wb") as fw:
        fw.write(data)
    return name


class EditorHandler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")   # 编辑器/配置永远是最新：禁缓存
        super().end_headers()

    def send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── GET：静态文件 + /__editor_stat ─────────────────────────────────────
    def do_GET(self):
        u = urlsplit(self.path)
        if u.path == "/__editor_stat":
            qs = parse_qs(u.query)
            rel = unquote(qs.get("path", [""])[0])
            if not rel:
                self.send_json({"ok": True, "server": "editor-save"})   # 能力探测
                return
            full = resolve_under_root(rel)
            if not full:
                self.send_json({"ok": False, "error": "path out of scope"}, 400)
                return
            st = stat_ms(full)
            if not st:
                self.send_json({"ok": True, "mtime": 0, "size": 0})     # 目标不存在：空版本
            else:
                self.send_json({"ok": True, "mtime": st["mtime"], "size": st["size"]})
            return
        super().do_GET()

    # ── POST：/__editor_save ────────────────────────────────────────────────
    def do_POST(self):
        u = urlsplit(self.path)
        if u.path != "/__editor_save":
            self.send_json({"ok": False, "error": "not found"}, 404)
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > MAX_BODY:
                self.send_json({"ok": False, "error": "bad content length"}, 400)
                return
            req = json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception as e:
            self.send_json({"ok": False, "error": "bad request: %s" % e}, 400)
            return

        rel = req.get("path") or ""
        content = req.get("content")
        if not isinstance(content, str):
            self.send_json({"ok": False, "error": "content must be string"}, 400)
            return
        full = resolve_under_root(rel)
        if not full:
            self.send_json({"ok": False, "error": "path out of scope（仅限服务器启动目录内的 .json）"}, 400)
            return

        # ★#2010 乐观锁：磁盘当前版本 vs 客户端已知版本
        st = stat_ms(full)
        cm = int(req.get("client_mtime") or 0)
        cs = int(req.get("client_size") or 0)
        if st and (cm or cs):
            stale = False
            if cs and st["size"] != cs:
                stale = True
            if cm and abs(st["mtime"] - cm) > MTIME_TOL_MS:
                stale = True
            if stale:
                self.send_json({"ok": False, "error": "stale", "mtime": st["mtime"], "size": st["size"]}, 409)
                return

        # ★覆盖前备份：旧内容先复制到同目录「备份」文件夹（失败不阻断写回，但如实回报）
        backup_name = ""
        backup_err = ""
        try:
            backup_name = backup_copy(full)
        except Exception as e:
            backup_err = str(e)

        # 原子写回：临时文件 + os.replace
        parent = os.path.dirname(full)
        try:
            os.makedirs(parent, exist_ok=True)
            tmp = full + ".editor_tmp"
            with open(tmp, "w", encoding="utf-8", newline="") as fw:
                fw.write(content)
            os.replace(tmp, full)
        except Exception as e:
            self.send_json({"ok": False, "error": "write failed: %s" % e}, 500)
            return

        st2 = stat_ms(full) or {"mtime": 0, "size": 0}
        print("[editor-save] %s ← %d bytes%s%s" % (
            rel, len(content.encode("utf-8")),
            (" ｜覆盖前副本 → %s/%s" % (BACKUP_DIR_NAME, backup_name)) if backup_name else "",
            (" ｜⚠️ 备份失败：%s" % backup_err) if backup_err else ""), flush=True)
        self.send_json({"ok": True, "mtime": st2["mtime"], "size": st2["size"], "backup": backup_name})

    def log_message(self, fmt, *args):   # 静态请求沿用默认日志，写盘已单独留痕
        super().log_message(fmt, *args)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    srv = ThreadingHTTPServer(("127.0.0.1", port), EditorHandler)
    print("短路表编辑器服务器已启动：http://127.0.0.1:%d/  （可写 ROOT=%s）" % (port, ROOT), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
