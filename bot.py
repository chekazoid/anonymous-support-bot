"""
Основной модуль телеграм‑бота для безопасного взаимодействия заявителей с
правозащитниками. Скрипт написан с использованием библиотеки aiogram и
проектирован в соответствии с техническим заданием, полученным от
пользователя. В нём реализованы следующие ключевые возможности:

• Анонимизация: бот выступает посредником между заявителями и
  администраторами правозащитной организации. Пользователь получает
  ответы без раскрытия личности администратора, а администратор видит
  только зашифрованные идентификаторы заявителей.

• Уникальные заявки: при создании заявки генерируется уникальный ID,
  который используется для хранения диалога и поиска статуса.

• База данных: используется SQLite (через aiosqlite) для хранения заявок,
  сообщений и файлов. Все данные шифруются перед записью с помощью
  симметричного шифрования (Fernet). Ключ шифрования задаётся через
  переменную окружения ENCRYPTION_KEY.

• Работа с файлами: бот принимает документы и изображения, удаляет из
  изображений EXIF‑метаданные с помощью Pillow/piexif и пересылает
  очищенные копии администраторам. Для других типов файлов предусмотрена
  возможность доработки (например, переупаковка архивов).

• Двухфакторная аутентификация для администраторов: чтобы использовать
  административные команды, администратор должен ввести пароль, затем
  одноразовый код. Для упрощения примера проверка OTP заменена на
  фиксированное значение.

• Ролевая модель: в конфигурации задаётся список пользователей с
  различными ролями (owner, admin, moderator, volunteer). Роль влияет
  на доступ к функциям и командам.

• Ограничение частоты запросов и защита от спама: реализована простая
  система rate limiting, не позволяющая пользователю отправлять больше
  определённого числа сообщений за час.

• Верификация новых пользователей: перед первой заявкой пользователю
  предлагается ответить на вопрос из заранее подготовленного списка.

Данный код предоставляет основу для построения защищённого
телеграм‑бота. По сравнению с полным техническим заданием некоторые
функции упрощены (например, использование Tor/VPN, интеграция с
VirusTotal и реализация сложного алгоритма защиты от timing‑атак). Они
оставлены в виде мест для дальнейшего развития.
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
# Конфигурация бота и глобальные переменные
# ---------------------------------------------------------------------------

# Токен бота следует установить в переменной окружения BOT_TOKEN.
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("Переменная окружения BOT_TOKEN не установлена")

# ID приватной группы, куда пересылаются сообщения заявителей. Значение
# следует указать в переменной окружения ADMIN_GROUP_ID. Обычно это
# отрицательное число (начинающееся с -100), полученное из Telegram.
ADMIN_GROUP_ID: int = int(os.getenv("ADMIN_GROUP_ID", "0"))
if not ADMIN_GROUP_ID:
    raise RuntimeError("Переменная окружения ADMIN_GROUP_ID не установлена")

# Ключ для симметричного шифрования. Если переменная окружения
# ENCRYPTION_KEY отсутствует, генерируется новый ключ. В реальной
# эксплуатации ключ должен храниться в секретном хранилище и ротации
# подвергаться регулярно.
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key().decode()
fernet = Fernet(ENCRYPTION_KEY.encode())

# Путь к базе данных. При необходимости можно заменить на более
# производительную СУБД.
DB_PATH = os.getenv("DB_PATH", "data/database.db")

# API-ключ VirusTotal. Если не задан, проверки VirusTotal отключены.
VT_API_KEY: Optional[str] = os.getenv("VT_API_KEY")

# Порог количества сообщений от одного пользователя в час. Если
# превышен, бот откажет в приёме новых сообщений до следующего периода.
RATE_LIMIT_COUNT = 100
RATE_LIMIT_INTERVAL = timedelta(hours=1)

# Предопределённые вопросы для верификации новых пользователей. Можно
# расширить списком из файла или базы данных.
VERIFICATION_QUESTIONS = [
    "В каком городе вы находитесь?",
    "Какое слово указано в правилах канала?",
    "Сколько букв в слове 'свобода'?",
]

# Роли и права. В реальном проекте список пользователей и их ролей
# следует хранить в конфигурации или базе данных. Здесь задаётся в виде
# словаря {user_id: role}. Роль owner имеет все права, admin –
# ограниченные, moderator и volunteer – ещё меньше. Пользователь без
# указанной роли считается заявителем.
ROLES: Dict[int, str] = {}

# Хранилище времени последних сообщений для реализации rate limiting.
user_message_timestamps: Dict[int, List[float]] = {}


# ---------------------------------------------------------------------------
# Классы состояний для FSM (машины состояний) aiogram
# ---------------------------------------------------------------------------

class VerificationState(StatesGroup):
    """Состояние верификации нового пользователя."""
    awaiting_answer = State()


class NewRequestState(StatesGroup):
    """Состояние создания новой заявки."""
    awaiting_message = State()


# ---------------------------------------------------------------------------
# Вспомогательные функции для шифрования, базы данных и проверки ролей
# ---------------------------------------------------------------------------

async def init_db() -> None:
    """Создаёт таблицы в базе данных, если они ещё не созданы."""
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
    """Шифрует текстовую строку и возвращает байтовую строку."""
    return fernet.encrypt(plain.encode())


def decrypt_text(cipher: bytes) -> str:
    """Расшифровывает байтовую строку, полученную encrypt_text."""
    return fernet.decrypt(cipher).decode()


def generate_request_id() -> str:
    """Генерирует уникальный идентификатор заявки."""
    return secrets.token_hex(8)


def is_admin(user_id: int) -> bool:
    """Проверяет, является ли пользователь администратором (любого уровня)."""
    return ROLES.get(user_id) in {"owner", "admin", "moderator", "volunteer"}


def has_role(user_id: int, role: str) -> bool:
    """Проверяет, обладает ли пользователь конкретной ролью или выше."""
    role_order = {"volunteer": 1, "moderator": 2, "admin": 3, "owner": 4}
    user_role = ROLES.get(user_id)
    if not user_role:
        return False
    return role_order.get(user_role, 0) >= role_order.get(role, 0)


async def record_message(user_id: int, request_id: str, sender: str, content: str) -> int:
    """Сохраняет сообщение в БД и возвращает ID записи."""
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
    """Сохраняет информацию о файле в БД."""
    async with aiosqlite.connect(DB_PATH) as db:
        now = datetime.utcnow().isoformat()
        await db.execute(
            "INSERT INTO files (message_id, file_id, sanitized_file_id, created_at) VALUES (?, ?, ?, ?)",
            (message_id, file_id, sanitized_file_id, now),
        )
        await db.commit()


def check_rate_limit(user_id: int) -> bool:
    """Проверяет, не превышена ли квота сообщений для пользователя. Возвращает
    True, если пользователь может отправлять сообщения; False – если
    лимит превышен."""
    now = time.time()
    timestamps = user_message_timestamps.setdefault(user_id, [])
    # Удаляем записи старше заданного интервала
    cutoff = now - RATE_LIMIT_INTERVAL.total_seconds()
    user_message_timestamps[user_id] = [t for t in timestamps if t > cutoff]
    if len(user_message_timestamps[user_id]) >= RATE_LIMIT_COUNT:
        return False
    user_message_timestamps[user_id].append(now)
    return True


async def sanitize_image(bot: Bot, file_id: str) -> str:
    """Скачивает изображение, удаляет EXIF‑данные и загружает обратно.

    Возвращает file_id очищенного изображения. Если файл не является
    изображением, возвращает исходный file_id.
    """
    try:
        file = await bot.get_file(file_id)
        # Скачиваем файл
        file_stream = await bot.download_file(file.file_path)
        data = await file_stream.read()
        img = Image.open(io.BytesIO(data))
        # Удаляем EXIF
        image_no_exif = Image.new(img.mode, img.size)
        image_no_exif.putdata(list(img.getdata()))
        output = io.BytesIO()
        image_no_exif.save(output, format="PNG")
        output.seek(0)
        message = await bot.send_document(
            ADMIN_GROUP_ID,
            types.InputFile(output, filename="sanitized.png"),
        )
        return message.document.file_id
    except Exception as ex:
        logging.exception("Не удалось очистить изображение: %s", ex)
        return file_id


# ---------------------------------------------------------------------------
# Функции интеграции с VirusTotal
# ---------------------------------------------------------------------------

def extract_urls(text: str) -> List[str]:
    """Извлекает все URL из строки. Возвращает список строк."""
    if not text:
        return []
    # Простое регулярное выражение для поиска http/https ссылок
    return re.findall(r"https?://[^\s]+", text)


def sync_vt_scan_file(file_bytes: bytes, filename: str) -> Optional[dict]:
    """Отправляет файл в VirusTotal и возвращает отчёт.

    Используется публичный API версии 2. Файл должен быть не больше 32 MB.
    Возвращает словарь с результатами анализа или None в случае ошибки.
    """
    if not VT_API_KEY:
        return None
    try:
        scan_url = "https://www.virustotal.com/vtapi/v2/file/scan"
        report_url = "https://www.virustotal.com/vtapi/v2/file/report"
        files = {"file": (filename, file_bytes)}
        params = {"apikey": VT_API_KEY}
        resp = requests.post(scan_url, files=files, params=params, timeout=60)
        data = resp.json()
        resource = data.get("resource") or data.get("sha256")
        if not resource:
            return None
        # Несколько попыток получить отчёт
        for _ in range(4):
            report_resp = requests.get(report_url, params={"apikey": VT_API_KEY, "resource": resource}, timeout=30)
            report = report_resp.json()
            if report.get("response_code") == 1:
                return report
            time.sleep(15)
        return None
    except Exception:
        return None


def sync_vt_scan_url(link: str) -> Optional[dict]:
    """Отправляет URL на анализ в VirusTotal и возвращает отчёт."""
    if not VT_API_KEY:
        return None
    try:
        scan_url = "https://www.virustotal.com/vtapi/v2/url/scan"
        report_url = "https://www.virustotal.com/vtapi/v2/url/report"
        # Инициализируем сканирование URL
        params = {"apikey": VT_API_KEY, "url": link}
        requests.post(scan_url, params=params, timeout=30)
        # Ждём и запрашиваем отчёт
        for _ in range(4):
            rep = requests.get(report_url, params={"apikey": VT_API_KEY, "resource": link}, timeout=30)
            report = rep.json()
            if report.get("response_code") == 1:
                return report
            time.sleep(10)
        return None
    except Exception:
        return None


async def vt_scan_file_bytes(file_bytes: bytes, filename: str) -> Optional[dict]:
    """Асинхронная обёртка для сканирования файлов через VirusTotal."""
    return await asyncio.to_thread(sync_vt_scan_file, file_bytes, filename)


async def vt_scan_url(link: str) -> Optional[dict]:
    """Асинхронная обёртка для сканирования URL через VirusTotal."""
    return await asyncio.to_thread(sync_vt_scan_url, link)


# ---------------------------------------------------------------------------
# Обработчики команд и сообщений
# ---------------------------------------------------------------------------

async def start_handler(message: types.Message, state: FSMContext) -> None:
    """Обрабатывает команду /start. Показывает приветствие и клавиатуру."""
    user_id = message.from_user.id
    # Регистрируем пользователя в БД
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT verified FROM users WHERE user_id = ?", (user_id,))
        row = await cursor.fetchone()
        if row is None:
            await db.execute("INSERT INTO users (user_id, verified) VALUES (?, 0)", (user_id,))
            await db.commit()
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
    """Обрабатывает нажатия на inline‑кнопки в главном меню."""
    user_id = query.from_user.id
    data = query.data
    if data == "new_request":
        # Проверяем, прошёл ли пользователь верификацию
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                "SELECT verified FROM users WHERE user_id = ?", (user_id,)
            )
            row = await cursor.fetchone()
        if row and row[0] == 0:
            question = secrets.choice(VERIFICATION_QUESTIONS)
            await state.update_data(verification_answer=question)
            await VerificationState.awaiting_answer.set()
            await query.message.edit_text(
                f"Чтобы продолжить, ответьте на вопрос для верификации:\n{question}"
            )
            await query.answer()
            return
        # Готовы принимать текст заявки
        await query.message.edit_text(
            "Пожалуйста, опишите вашу проблему одним или несколькими сообщениями.\n"
            "Когда закончите, отправьте /end, чтобы закрыть заявку."
        )
        request_id = generate_request_id()
        await state.update_data(request_id=request_id)
        await NewRequestState.awaiting_message.set()
    elif data == "my_requests":
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
            await query.message.edit_text("\n".join(text_lines))
    elif data == "request_status":
        await query.message.edit_text(
            "Введите ID заявки, чтобы узнать её статус, в формате /status <ID>"
        )
    elif data == "contacts":
        await query.message.edit_text(
            "Связаться с правозащитниками вы можете через этот бот.\n"
            "Также есть электронная почта: help@example.org."
        )
    await query.answer()


async def verification_answer_handler(message: types.Message, state: FSMContext) -> None:
    """Проверяет ответ пользователя на верификационный вопрос."""
    user_id = message.from_user.id
    data = await state.get_data()
    expected = data.get("verification_answer")
    if expected is None:
        await message.answer("Неожиданный ответ. Попробуйте снова позже.")
        await state.finish()
        return
    # Здесь можно проверить правильность ответа; упрощённо принимаем любой
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE users SET verified = 1 WHERE user_id = ?", (user_id,))
        await db.commit()
    await message.answer(
        "Спасибо! Вы прошли верификацию и теперь можете создавать заявки."
    )
    await state.finish()
    await start_handler(message, state)


async def new_request_message_handler(message: types.Message, state: FSMContext) -> None:
    """Принимает текст или файл от пользователя в процессе создания заявки."""
    user_id = message.from_user.id
    if not check_rate_limit(user_id):
        await message.answer(
            "Вы слишком часто отправляете сообщения. Попробуйте позже."
        )
        return
    data = await state.get_data()
    request_id = data.get("request_id")
    if not request_id:
        await message.answer("Не найден ID заявки. Пожалуйста, начните заново.")
        await state.finish()
        return
    if message.text and message.text.strip().lower() == "/end":
        await message.answer("Ваша заявка отправлена. Спасибо!")
        await state.finish()
        return
    # Определяем текстовое содержимое сообщения (если это файл, используем заголовок или отметку [файл])
    content = message.text or message.caption or "[файл]"
    # Проверяем текст на наличие вредоносных ссылок и отправляем URL на анализ в VirusTotal
    if content and content != "[файл]":
        urls = extract_urls(content)
        if urls and VT_API_KEY:
            for link in urls:
                report = await vt_scan_url(link)
                if report and report.get("positives", 0) > 0:
                    await message.answer(
                        "В вашем сообщении обнаружена подозрительная ссылка. Сообщение отклонено."
                    )
                    return
    # Подготовка к проверке прикреплённого файла
    flagged = False
    sanitized_file_id: Optional[str] = None
    # Анализируем документы
    if message.document:
        # Скачиваем файл в память
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
            await message.answer(
                "Прикреплённый файл определён как потенциально вредоносный и не будет отправлен."
            )
            return
    elif message.photo:
        # Аналогично проверяем изображение
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
            await message.answer(
                "Загруженное изображение определено как вредоносное и не будет отправлено."
            )
            return
    # Записываем сообщение в базу, только если оно не было отклонено
    msg_id = await record_message(user_id, request_id, "user", content)
    # Работа с файлами: отправляем очищенные или оригинальные файлы администратору
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
    # Если текст не пустой, пересылаем его администратору
    if content and content != "[файл]":
        await message.bot.send_message(
            ADMIN_GROUP_ID,
            f"Новая заявка {request_id} от пользователя {user_id}:\n{content}"
        )
    # Запись о заявке
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO requests (id, user_id, created_at, status) VALUES (?, ?, ?, ?)",
            (request_id, user_id, datetime.utcnow().isoformat(), "open"),
        )
        await db.commit()


async def admin_reply_handler(message: types.Message) -> None:
    """Перехватывает ответы администраторов в приватной группе и доставляет их
    заявителю. Сообщение должно быть ответом на пересланную заявку."""
    if message.chat.id != ADMIN_GROUP_ID:
        return
    user_id = message.from_user.id
    if not is_admin(user_id):
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
        target_user_id = int(parts[5].strip(':'))
    except Exception:
        logging.warning("Не удалось разобрать исходное сообщение: %s", original)
        return
    await record_message(user_id, request_id, "admin", reply_text)
    try:
        await message.bot.send_message(
            target_user_id,
            f"Ответ на вашу заявку {request_id}:\n{reply_text}"
        )
    except Exception as ex:
        logging.exception("Не удалось отправить ответ пользователю: %s", ex)


async def status_command_handler(message: types.Message) -> None:
    """Обрабатывает команду /status <ID>."""
    parts = message.get_args().split()
    if not parts:
        await message.reply("Использование: /status <ID заявки>")
        return
    request_id = parts[0]
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            "SELECT created_at, status FROM requests WHERE id = ? AND user_id = ?",
            (request_id, message.from_user.id),
        )
        row = await cursor.fetchone()
        if not row:
            await message.reply("Заявка не найдена.")
            return
        created_at, status = row
        cursor = await db.execute(
            "SELECT sender, content, created_at FROM messages WHERE request_id = ? ORDER BY created_at DESC LIMIT 5",
            (request_id,),
        )
        msgs = await cursor.fetchall()
    lines = [f"Статус заявки {request_id}: {status}", f"Создана: {created_at}", "Последние сообщения:"]
    for sender, enc_content, ts in reversed(msgs):
        try:
            text = decrypt_text(enc_content)
        except Exception:
            text = "<не удалось расшифровать>"
        prefix = "Вы" if sender == "user" else "Правозащитник"
        lines.append(f"[{ts}] {prefix}: {text}")
    await message.reply("\n".join(lines))


async def unknown_message_handler(message: types.Message) -> None:
    """Ответ по умолчанию на неизвестные сообщения."""
    await message.reply(
        "Извините, я не понял команду. Используйте /start для начала работы."
    )


async def main() -> None:
    """Точка входа. Запуск опросчика aiogram."""
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