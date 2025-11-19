import os
import datetime
from typing import Optional, List

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import aiosqlite
from dotenv import load_dotenv
from cryptography.fernet import Fernet
import requests

load_dotenv()
DB_PATH = os.getenv("DB_PATH", "data/database.db")
BOT_TOKEN = os.getenv("BOT_TOKEN")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
fernet = Fernet(ENCRYPTION_KEY.encode()) if ENCRYPTION_KEY else None

app = FastAPI()
templates = Jinja2Templates(directory="templates")

def decrypt_text(cipher: bytes) -> str:
    if not cipher:
        return ""
    if not fernet:
        return cipher.decode()
    return fernet.decrypt(cipher).decode()

@app.get("/webapp", response_class=HTMLResponse)
async def list_requests(request: Request, page: int = 1, query_id: Optional[str] = None,
                        user_id: Optional[str] = None, date: Optional[str] = None):
    page_size = 10
    offset = (page - 1) * page_size
    sql = "SELECT id, user_id, created_at, status FROM requests"
    conditions: List[str] = []
    params: List = []
    if query_id:
        conditions.append("id = ?")
        params.append(query_id)
    if user_id:
        try:
            uid_int = int(user_id)
            conditions.append("user_id = ?")
            params.append(uid_int)
        except ValueError:
            pass
    if date:
        conditions.append("substr(created_at, 1, 10) = ?")
        params.append(date)
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY datetime(created_at) DESC LIMIT ? OFFSET ?"
    params.extend([page_size + 1, offset])
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(sql, params)
        rows = await cursor.fetchall()
    has_next = False
    if len(rows) > page_size:
        has_next = True
        rows = rows[:page_size]
    requests_list = [{"id": r[0], "user_id": r[1], "created_at": r[2], "status": r[3]} for r in rows]
    return templates.TemplateResponse("requests_list.html", {"request": request, "requests": requests_list,
                                                            "page": page, "has_next": has_next})

@app.get("/webapp/requests/{request_id}", response_class=HTMLResponse)
async def request_detail(request: Request, request_id: str):
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT user_id, created_at, status FROM requests WHERE id = ?", (request_id,))
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Заявка не найдена")
        user_id, created_at, status = row
        cursor = await db.execute(
            "SELECT sender, content, created_at FROM messages WHERE request_id = ? ORDER BY datetime(created_at)",
            (request_id,))
        msgs = await cursor.fetchall()
    messages = []
    for sender, content, ts in msgs:
        try:
            text = decrypt_text(content)
        except Exception:
            text = "<не удалось расшифровать>"
        messages.append({"sender": sender, "text": text, "time": ts})
    data = {
        "request": {"id": request_id, "user_id": user_id, "created_at": created_at, "status": status},
        "messages": messages
    }
    return templates.TemplateResponse("request_detail.html", {"request": request, **data})

@app.post("/webapp/requests/{request_id}/reply", response_class=HTMLResponse)
async def reply_request(request: Request, request_id: str, reply_text: str = Form(...)):
    async with aiosqlite.connect(DB_PATH) as db:
        now = datetime.datetime.utcnow().isoformat()
        enc = fernet.encrypt(reply_text.encode()) if fernet else reply_text.encode()
        await db.execute(
            "INSERT INTO messages (request_id, sender, content, created_at) VALUES (?, ?, ?, ?)",
            (request_id, "admin", enc, now)
        )
        await db.commit()
        cursor = await db.execute("SELECT user_id FROM requests WHERE id = ?", (request_id,))
        row = await cursor.fetchone()
    if row:
        target_user_id = row[0]
        if BOT_TOKEN:
            url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
            payload = {"chat_id": target_user_id, "text": f"Ответ на вашу заявку {request_id}:\n{reply_text}"}
            try:
                requests.post(url, json=payload, timeout=5)
            except Exception:
                pass
    return await request_detail(request, request_id)

@app.post("/webapp/requests/{request_id}/close", response_class=HTMLResponse)
async def close_request(request: Request, request_id: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE requests SET status = 'closed' WHERE id = ?", (request_id,))
        await db.commit()
    return HTMLResponse(content="<p>Заявка закрыта.</p>")

@app.get("/webapp/stats", response_class=HTMLResponse)
async def stats(request: Request):
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT status, COUNT(*) FROM requests GROUP BY status")
        stats_rows = await cursor.fetchall()
        counts = {status: count for status, count in stats_rows}
        cursor = await db.execute(
            "SELECT r.created_at, MIN(m.created_at) FROM requests r JOIN messages m "
            "ON r.id = m.request_id AND m.sender = 'admin' GROUP BY r.id"
        )
        rows = await cursor.fetchall()
        total_diff = 0
        count = 0
        for created_at, first_reply in rows:
            if first_reply:
                try:
                    t0 = datetime.datetime.fromisoformat(created_at)
                    t1 = datetime.datetime.fromisoformat(first_reply)
                    diff = (t1 - t0).total_seconds()
                    if diff >= 0:
                        total_diff += diff
                        count += 1
                except Exception:
                    pass
        avg_resp_time = None
        if count:
            avg_resp_time = datetime.timedelta(seconds=int(total_diff / count))
        cursor = await db.execute(
            "SELECT substr(created_at, 1, 10) as date, COUNT(*) FROM requests GROUP BY date ORDER BY date"
        )
        activity = await cursor.fetchall()
    return templates.TemplateResponse("stats.html", {"request": request,
                                                    "open_count": counts.get("open", 0),
                                                    "closed_count": counts.get("closed", 0),
                                                    "avg_resp_time": avg_resp_time,
                                                    "activity": activity})
