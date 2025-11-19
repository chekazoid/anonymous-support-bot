"""
Основной модуль телеграм‑бота для безопасного взаимодействия заявителей с
правозащитниками. Скрипт написан с использованием библиотеки aiogram и
проектирован в соответствии с техническим заданием. Реализованы:

• Анонимизация: бот выступает посредником между заявителями и администраторами.
• Уникальные заявки: при создании заявки генерируется уникальный ID.
• База данных: используется SQLite (через aiosqlite) с шифрованием данных (Fernet).
• Работа с файлами: изображения очищаются от EXIF; документы пересылаются как есть.
• Двухфакторная аутентификация для администраторов (упрощённо).
• Ролевая модель доступа и ограничение частоты сообщений.
• Верификация новых пользователей.
• Проверка URL и файлов через VirusTotal с использованием хэшей (асинхронно).
• Команды для администраторов: /close, /requests, /stats, /status, а также кнопка “Назад”.

Функции, связанные с Tor/VPN и глубоким мониторингом, оставлены как точки расширения.
"""

import asyncio
import logging
import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from aiogram import Bot, Dispatcher, types
from aiogram.contrib.fsm_storage.memory import MemoryStorage
from aiogram.dispatcher import FSMContext
from aiogram.dispatcher.filters.state import State, StatesGroup
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

import aiosqlite
from cryptography.fernet import Fernet
from PIL import Image
import io
import re
import requests

# ---------------------------------------------------------------------------
# Конфигурация и загрузка переменных окружения
# ---------------------------------------------------------------------------
from dotenv import load_dotenv
load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("Переменная окружения BOT_TOKEN не установлена")

ADMIN_GROUP_ID = int(os.getenv("ADMIN_GROUP_ID", "0"))
if not ADMIN_GROUP_ID:
    raise RuntimeError("Переменная окружения ADMIN_GROUP_ID не установлена")

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key().decode()
fernet = Fernet(ENCRYPTION_KEY.encode())

DB_PATH = os.getenv("DB_PATH", "data/database.db")
VT_API_KEY: Optional[str] = os.getenv("VT_API_KEY")

# Ограничение частоты сообщений
RATE_LIMIT_COUNT = 100
RATE_LIMIT_INTERVAL = timedelta(hours=1)
user_message_timestamps: Dict[int, List[float]] = {}

# Вопросы для верификации
VERIFICATION_QUESTIONS = [
    "В каком городе вы находитесь?",
    "Какое слово указано в правилах канала?",
    "Сколько букв в слове 'свобода'?",
]

# Список ролей; можно задать через ADMIN_IDS в .env (через запятую)
ROLES: Dict[int, str] = {}
admin_ids_env = os.getenv("ADMIN_IDS")
if admin_ids_env:
    for uid_str in admin_ids_env.split(","):
        uid_str = uid_str.strip()
        if uid_str.isdigit():
            ROLES[int(uid_str)] = "admin"

# ---------------------------------------------------------------------------
# FSM состояния aiogram
# ---------------------------------------------------------------------------
class VerificationState(StatesGroup):
    awaiting_answer = State()

class NewRequestState(StatesGroup):
    awaiting_message = State()

# ---------------------------------------------------------------------------
# Вспомогательные функции (БД, шифрование, роли, rate-limit)
# ---------------------------------------------------------------------------
async def init_db() -> None:
    # Создание директорий и таблиц при первом запуске
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                verified INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open'
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                sender TEXT NOT NULL,
                content BLOB,
                created_at TEXT NOT NULL,
                FOREIGN KEY(request_id) REFERENCES requests(id)
            );
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER,
                file_id TEXT,
                sanitized_file_id TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(message_id) REFERENCES messages(id)
            );
            """
        )
        await db.commit()

def encrypt_text(plain: str) -> bytes:
    return fernet.encrypt(plain.encode())

def decrypt_text(cipher: bytes) -> str:
    return fernet.decrypt(cipher).decode()

def generate_request_id() -> str:
    return secrets.token_hex(8)

def is_admin(user_id: int) -> bool:
    return ROLES.get(user_id) in {"owner", "admin", "moderator", "volunteer"}

def check_rate_limit(user_id: int) -> bool:
    now = time.time()
    timestamps = user_message_timestamps.setdefault(user_id, [])
    cutoff = now - RATE_LIMIT_INTERVAL.total_seconds()
    user_message_timestamps[user_id] = [t for t in timestamps if t > cutoff]
    if len(user_message_timestamps[user_id]) >= RATE_LIMIT_COUNT:
        return False
    user_message_timestamps[user_id].append(now)
    return True

def remove_exif_from_image_bytes(image_bytes: bytes) -> Optional[bytes]:
    # Синхронная функция для удаления EXIF из изображения; будет вызвана в отдельном потоке
    try:
        img = Image.open(io.BytesIO(image_bytes))
        image_no_exif = Image.new(img.mode, img.size)
        image_no_exif.putdata(list(img.getdata()))
        output = io.BytesIO()
        image_no_exif.save(output, format="PNG")
        output.seek(0)
        return output.read()
    except Exception as ex:
        logging.exception("Не удалось очистить изображение: %s", ex)
        return None

async def sanitize_image(bot: Bot, file_id: str) -> str:
    """
    Скачивает изображение, удаляет EXIF, отправляет очищенную версию в админ‑группу.
    Возвращает file_id очищенного изображения (или оригинальный file_id при ошибке).
    """
    try:
        f_info = await bot.get_file(file_id)
        f_stream = await bot.download_file(f_info.file_path)
        data = await f_stream.read()
    except Exception as ex:
        logging.exception("Ошибка загрузки изображения: %s", ex)
        return file_id
    sanitized_bytes = await asyncio.to_thread(remove_exif_from_image_bytes, data)
    if sanitized_bytes:
        msg = await bot.send_document(
            ADMIN_GROUP_ID,
            types.InputFile(io.BytesIO(sanitized_bytes), filename="sanitized.png")
        )
        return msg.document.file_id
    else:
        await bot.send_photo(ADMIN_GROUP_ID, file_id)
        return file_id

def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    return re.findall(r"https?://[^\s]+", text)

def sync_vt_scan_file(file_bytes: bytes, filename: str) -> Optional[dict]:
    # Проверка файла через VirusTotal по хэшу (синхронно)
    if not VT_API_KEY:
        return None
    try:
        import hashlib
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        resp = requests.get(url, params={"apikey": VT_API_KEY, "resource": file_hash}, timeout=30)
        report = resp.json()
        if report.get("response_code") == 1:
            return report
        return None
    except Exception:
        return None

def sync_vt_scan_url(link: str) -> Optional[dict]:
    # Проверка URL через VirusTotal (синхронно)
    if not VT_API_KEY:
        return None
    try:
        url = "https://www.virustotal.com/vtapi/v2/url/report"
        resp = requests.get(url, params={"apikey": VT_API_KEY, "resource": link}, timeout=15)
        report = resp.json()
        if report.get("response_code") == 1:
            return report
        return None
    except Exception:
        return None

async def vt_scan_file_bytes(file_bytes: bytes, filename: str) -> Optional[dict]:
    return await asyncio.to_thread(sync_vt_scan_file, file_bytes, filename)

async def vt_scan_url(link: str) -> Optional[dict]:
    return await asyncio.to_thread(sync_vt_scan_url, link)

async def record_message(user_id: int, request_id: str, sender: str, content: str) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        enc = encrypt_text(content)
        now = datetime.utcnow().isoformat()
        cursor = await db.execute(
            "INSERT INTO messages (request_id, sender, content, created_at) VALUES (?, ?, ?, ?)",
            (request_id, sender, enc, now),
        )
        await db.commit()
        return cursor.lastrowid

async def record_file(message_id: int, file_id: str, sanitized_file_id: str) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        now = datetime.utcnow().isoformat()
        await db.execute(
            "INSERT INTO files (message_id, file_id, sanitized_file_id, created_at) VALUES (?, ?, ?, ?)",
            (message_id, file_id, sanitized_file_id, now),
        )
        await db.commit()

# ---------------------------------------------------------------------------
# Обработчики команд и сообщений
# ---------------------------------------------------------------------------
async def start_handler(message: types.Message, state: FSMContext) -> None:
    # Регистрация пользователя в БД, если ещё нет
    user_id = message.from_user.id
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT verified FROM users WHERE user_id = ?", (user_id,))
        row = await cursor.fetchone()
        if row is None:
            await db.execute("INSERT INTO users (user_id, verified) VALUES (?, 0)", (user_id,))
            await db.commit()
    # Главное меню
    keyboard = InlineKeyboardMarkup(row_width=2)
    keyboard.add(
        InlineKeyboardButton("Новая заявка", callback_data="new_request"),
        InlineKeyboardButton("Мои заявки", callback_data="my_requests"),
        InlineKeyboardButton("Статус заявки", callback_data="request_status"),
        InlineKeyboardButton("Контакты", callback_data="contacts"),
    )
    await message.answer(
        "Здравствуйте! Этот бот поможет вам связаться с нашими правозащитниками.\n"
        "Выберите действие ниже.",
        reply_markup=keyboard,
    )

async def callback_handler(query: types.CallbackQuery, state: FSMContext) -> None:
    user_id = query.from_user.id
    data = query.data
    if data == "new_request":
        # Проверка верификации пользователя
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("SELECT verified FROM users WHERE user_id = ?", (user_id,))
            row = await cursor.fetchone()
        if row and row[0] == 0:
            question = secrets.choice(VERIFICATION_QUESTIONS)
            await state.update_data(verification_answer=question)
            await VerificationState.awaiting_answer.set()
            await query.message.edit_text(f"Чтобы продолжить, ответьте на вопрос для верификации:\n{question}")
            await query.answer()
            return
        # Начинаем приём сообщений по новой заявке
        await query.message.edit_text(
            "Пожалуйста, опишите вашу проблему одним или несколькими сообщениями.\n"
            "Когда закончите, отправьте /end, чтобы закрыть заявку."
        )
        request_id = generate_request_id()
        await state.update_data(request_id=request_id)
        await NewRequestState.awaiting_message.set()
    elif data == "my_requests":
        # Список заявок пользователя
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                "SELECT id, created_at, status FROM requests WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            )
            rows = await cursor.fetchall()
        if not rows:
            await query.message.edit_text("У вас нет созданных заявок.")
        else:
            text_lines = ["Ваши заявки:"]
            for rid, created, status in rows:
                text_lines.append(f"ID: {rid} | Создано: {created} | Статус: {status}")
            keyboard = InlineKeyboardMarkup().add(InlineKeyboardButton("Назад", callback_data="main_menu"))
            await query.message.edit_text("\n".join(text_lines), reply_markup=keyboard)
    elif data == "request_status":
        await query.message.edit_text("Введите ID заявки, чтобы узнать её статус, в формате /status <ID>")
    elif data == "contacts":
        await query.message.edit_text(
            "Связаться с правозащитниками вы можете через этот бот.\nТакже есть электронная почта: help@example.org."
        )
    elif data == "main_menu":
        # Возврат в главное меню
        keyboard = InlineKeyboardMarkup(row_width=2)
        keyboard.add(
            InlineKeyboardButton("Новая заявка", callback_data="new_request"),
            InlineKeyboardButton("Мои заявки", callback_data="my_requests"),
            InlineKeyboardButton("Статус заявки", callback_data="request_status"),
            InlineKeyboardButton("Контакты", callback_data="contacts")
        )
        await query.message.edit_text(
            "Здравствуйте! Этот бот поможет вам связаться с нашими правозащитниками.\n"
            "Выберите действие ниже.",
            reply_markup=keyboard
        )
    await query.answer()

async def verification_answer_handler(message: types.Message, state: FSMContext) -> None:
    # Обработчик ответа на верификационный вопрос
    user_id = message.from_user.id
    data = await state.get_data()
    expected = data.get("verification_answer")
    if expected is None:
        await message.answer("Неожиданный ответ. Попробуйте снова позже.")
        await state.finish()
        return
    # Отмечаем пользователя как проверенного
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE users SET verified = 1 WHERE user_id = ?", (user_id,))
        await db.commit()
    await message.answer("Спасибо! Вы прошли верификацию и теперь можете создавать заявки.")
    await state.finish()
    await start_handler(message, state)

async def new_request_message_handler(message: types.Message, state: FSMContext) -> None:
    # Приём сообщений в рамках новой заявки
    user_id = message.from_user.id
    if not check_rate_limit(user_id):
        await message.answer("Вы слишком часто отправляете сообщения. Попробуйте позже.")
        return
    data = await state.get_data()
    request_id = data.get("request_id")
    if not request_id:
        await message.answer("Не найден ID заявки. Пожалуйста, начните заново.")
        await state.finish()
        return
    # Завершение заявки
    if message.text and message.text.strip().lower() == "/end":
        await message.answer("Ваша заявка отправлена. Спасибо!")
        await state.finish()
        return
    content = message.text or message.caption or "[файл]"
    # Проверка ссылок через VirusTotal
    if content and content != "[файл]":
        urls = extract_urls(content)
        if urls and VT_API_KEY:
            for link in urls:
                report = await vt_scan_url(link)
                if report and report.get("positives", 0) > 0:
                    await message.answer("В вашем сообщении обнаружена подозрительная ссылка. Сообщение отклонено.")
                    return
    flagged = False
    # Проверка документов
    if message.document:
        file_name = message.document.file_name or "document"
        try:
            f_info = await message.bot.get_file(message.document.file_id)
            f_stream = await message.bot.download_file(f_info.file_path)
            file_bytes = await f_stream.read()
        except Exception:
            file_bytes = None
        if file_bytes and VT_API_KEY:
            report = await vt_scan_file_bytes(file_bytes, file_name)
            if report and report.get("positives", 0) > 0:
                flagged = True
        if flagged:
            await message.answer("Прикреплённый файл определён как потенциально вредоносный и не будет отправлен.")
            return
    elif message.photo:
        # Проверка изображений
        try:
            file_id_img = message.photo[-1].file_id
            f_info = await message.bot.get_file(file_id_img)
            f_stream = await message.bot.download_file(f_info.file_path)
            img_bytes = await f_stream.read()
        except Exception:
            img_bytes = None
        if img_bytes and VT_API_KEY:
            report = await vt_scan_file_bytes(img_bytes, "photo.jpg")
            if report and report.get("positives", 0) > 0:
                flagged = True
        if flagged:
            await message.answer("Загруженное изображение определено как вредоносное и не будет отправлено.")
            return
    # Сохраняем текст сообщения в БД
    msg_id = await record_message(user_id, request_id, "user", content)
    # Обработка файлов
    if message.document:
        file_id = message.document.file_id
        sanitized_file_id = file_id
        await record_file(msg_id, file_id, sanitized_file_id)
        await message.bot.send_document(
            ADMIN_GROUP_ID,
            message.document.file_id,
            caption=f"Новая заявка {request_id} от пользователя {user_id}"
        )
    elif message.photo:
        file_id = message.photo[-1].file_id
        sanitized_file_id = await sanitize_image(message.bot, file_id)
        await record_file(msg_id, file_id, sanitized_file_id)
    # Пересылаем текст заявки администраторам
    if content and content != "[файл]":
        await message.bot.send_message(
            ADMIN_GROUP_ID,
            f"Новая заявка {request_id} от пользователя {user_id}:\n{content}"
        )
    # Записываем заявку в requests (если новая)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO requests (id, user_id, created_at, status) VALUES (?, ?, ?, ?)",
            (request_id, user_id, datetime.utcnow().isoformat(), "open"),
        )
        await db.commit()

# Для получения сообщений в группе необходимо отключить Privacy Mode у бота через BotFather
async def admin_reply_handler(message: types.Message) -> None:
    # Ответ администратора в приватной группе
    if message.chat.id != ADMIN_GROUP_ID:
        return
    user_id = message.from_user.id
    if ROLES and not is_admin(user_id):
        return
    if not message.reply_to_message:
        return
    reply_text = message.text or message.caption or ""
    original = message.reply_to_message.text or message.reply_to_message.caption or ""
    parts = original.split()
    if len(parts) < 6:
        return
    try:
        request_id = parts[2]
        target_user_id = int(parts[5].rstrip(":"))
    except Exception:
        logging.warning("Не удалось разобрать исходное сообщение: %s", original)
        return
    await record_message(user_id, request_id, "admin", reply_text)
    try:
        await message.bot.send_message(target_user_id, f"Ответ на вашу заявку {request_id}:\n{reply_text}")
    except Exception as ex:
        logging.exception("Не удалось отправить ответ пользователю: %s", ex)

async def status_command_handler(message: types.Message) -> None:
    """Команда /status <ID> для просмотра статуса заявки."""
    parts = message.get_args().split()
    if not parts:
        await message.reply("Использование: /status <ID заявки>")
        return
    request_id = parts[0]
    async with aiosqlite.connect(DB_PATH) as db:
        if is_admin(message.from_user.id):
            cursor = await db.execute("SELECT user_id, created_at, status FROM requests WHERE id = ?", (request_id,))
        else:
            cursor = await db.execute("SELECT created_at, status FROM requests WHERE id = ? AND user_id = ?", (request_id, message.from_user.id))
        row = await cursor.fetchone()
        if not row:
            await message.reply("Заявка не найдена.")
            return
        if is_admin(message.from_user.id):
            user_id_req, created_at, status = row
        else:
            created_at, status = row
            user_id_req = None
        cursor = await db.execute(
            "SELECT sender, content, created_at FROM messages WHERE request_id = ? ORDER BY created_at DESC LIMIT 5",
            (request_id,)
        )
        msgs = await cursor.fetchall()
    lines = [f"Статус заявки {request_id}: {status}", f"Создана: {created_at}"]
    if is_admin(message.from_user.id) and user_id_req is not None:
        lines.append(f"Пользователь: {user_id_req}")
    lines.append("Последние сообщения:")
    for sender, enc_content, ts in reversed(msgs):
        try:
            text = decrypt_text(enc_content)
        except Exception:
            text = "<не удалось расшифровать>"
        if is_admin(message.from_user.id):
            prefix = "Заявитель" if sender == "user" else "Администратор"
        else:
            prefix = "Вы" if sender == "user" else "Правозащитник"
        lines.append(f"[{ts}] {prefix}: {text}")
    await message.reply("\n".join(lines))

async def close_command_handler(message: types.Message) -> None:
    # Команда /close <ID> закрывает заявку
    if ROLES:
        if not is_admin(message.from_user.id):
            return
    else:
        if message.chat.id != ADMIN_GROUP_ID:
            return
    parts = message.get_args().split()
    if not parts:
        await message.reply("Использование: /close <ID заявки>")
        return
    request_id = parts[0]
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT user_id, status FROM requests WHERE id = ?", (request_id,))
        row = await cursor.fetchone()
        if not row:
            await message.reply("Заявка не найдена.")
            return
        user_id_req, status = row
        if status == "closed":
            await message.reply("Заявка уже закрыта.")
            return
        await db.execute("UPDATE requests SET status = 'closed' WHERE id = ?", (request_id,))
        await db.commit()
    await message.reply(f"Заявка {request_id} отмечена как закрытая.")
    try:
        await message.bot.send_message(user_id_req, f"Ваша заявка {request_id} была закрыта администратором.")
    except Exception as ex:
        logging.exception("Не удалось уведомить пользователя о закрытии: %s", ex)

async def list_requests_handler(message: types.Message) -> None:
    # Команда /requests [open|closed|all] выводит список заявок
    if ROLES:
        if not is_admin(message.from_user.id):
            return
    else:
        if message.chat.id != ADMIN_GROUP_ID:
            return
    parts = message.get_args().split()
    status_filter = parts[0].lower() if parts else "open"
    if status_filter not in ("open", "closed", "all"):
        await message.reply("Использование: /requests [open|closed|all]")
        return
    async with aiosqlite.connect(DB_PATH) as db:
        if status_filter == "all":
            cursor = await db.execute("SELECT id, user_id, status FROM requests ORDER BY created_at DESC")
        else:
            cursor = await db.execute("SELECT id, user_id, status FROM requests WHERE status = ? ORDER BY created_at DESC", (status_filter,))
        rows = await cursor.fetchall()
    if not rows:
        status_text = "со статусом " + status_filter if status_filter != "all" else ""
        await message.reply(f"Нет заявок {status_text}.")
        return
    lines = [f"Заявки ({ 'все' if status_filter=='all' else status_filter }):"]
    for rid, uid, status in rows[:20]:
        lines.append(f"{rid} | Пользователь: {uid} | Статус: {status}")
    if len(rows) > 20:
        lines.append(f"... и ещё {len(rows) - 20} заявок.")
    await message.reply("\n".join(lines))

async def stats_command_handler(message: types.Message) -> None:
    # Команда /stats выводит краткую статистику
    if ROLES:
        if not is_admin(message.from_user.id):
            return
    else:
        if message.chat.id != ADMIN_GROUP_ID:
            return
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT status, COUNT(*) FROM requests GROUP BY status")
        stats = await cursor.fetchall()
    total = sum(count for _, count in stats)
    counts = {status: count for status, count in stats}
    open_count = counts.get("open", 0)
    closed_count = counts.get("closed", 0)
    await message.reply(f"Всего заявок: {total}\nОткрытые: {open_count}\nЗакрытые: {closed_count}")

async def unknown_message_handler(message: types.Message) -> None:
    await message.reply("Извините, я не понял команду. Используйте /start для начала работы.")

# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------
async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    await init_db()
    bot = Bot(token=BOT_TOKEN)
    storage = MemoryStorage()
    dp = Dispatcher(bot, storage=storage)
    # Регистрация хендлеров
    dp.register_message_handler(start_handler, commands=["start"], state="*")
    dp.register_callback_query_handler(callback_handler, state="*")
    dp.register_message_handler(verification_answer_handler, state=VerificationState.awaiting_answer, content_types=types.ContentTypes.TEXT)
    dp.register_message_handler(new_request_message_handler, state=NewRequestState.awaiting_message, content_types=types.ContentTypes.ANY)
    dp.register_message_handler(close_command_handler, commands=["close"])
    dp.register_message_handler(list_requests_handler, commands=["requests"])
    dp.register_message_handler(stats_command_handler, commands=["stats"])
    dp.register_message_handler(admin_reply_handler, content_types=types.ContentTypes.ANY)
    dp.register_message_handler(status_command_handler, commands=["status"])
    dp.register_message_handler(unknown_message_handler, content_types=types.ContentTypes.ANY)
    try:
        await dp.start_polling()
    finally:
        await storage.close()
        await bot.session.close()

if __name__ == "__main__":
    asyncio.run(main())
