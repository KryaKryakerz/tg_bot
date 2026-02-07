from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx
import jwt

try:
    import bcrypt
except Exception:  # pragma: no cover - optional dependency
    bcrypt = None

from aiogram import Bot, Dispatcher, F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import CallbackQuery, InlineKeyboardButton, Message
from aiogram.types.input_file import BufferedInputFile
from aiogram.utils.keyboard import InlineKeyboardBuilder

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000").rstrip("/")
ADMIN_FILE = os.getenv("ADMIN_FILE", "admins.json")
JWT_SECRET = os.getenv("JWT_SECRET", "d1eaf5666b5e7bb19fdf677e9f7ad0d3")
JWT_ALG = os.getenv("JWT_ALG", "HS256")
JWT_TTL_SECONDS = int(os.getenv("JWT_TTL_SECONDS", "3600"))
PAGE_SIZE = int(os.getenv("PAGE_SIZE", "10"))
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "15"))

if not BOT_TOKEN:
    raise RuntimeError("Не указан TELEGRAM_BOT_TOKEN")

router = Router()


class LoginStates(StatesGroup):
    waiting_login = State()
    waiting_password = State()


class TrialStates(StatesGroup):
    waiting_email = State()


@dataclass
class Session:
    username: str
    token: str
    expires_at: float


SESSIONS: Dict[int, Session] = {}
FILE_CACHE: Dict[int, List[str]] = {}


def _is_hex_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in value)


def verify_password(stored_hash: str, password: str) -> bool:
    if stored_hash.startswith("sha256:"):
        stored_hash = stored_hash.split(":", 1)[1]

    if stored_hash.startswith("$2"):
        if not bcrypt:
            logging.warning("bcrypt не установлен, проверить хэш нельзя")
            return False
        try:
            return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
        except ValueError:
            return False

    if _is_hex_sha256(stored_hash):
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return digest.lower() == stored_hash.lower()

    logging.warning("Неподдерживаемый формат хэша")
    return False


def load_admins(path: str) -> Dict[str, str]:
    admin_path = Path(path)
    if not admin_path.exists():
        logging.warning("Файл админов не найден: %s", path)
        return {}

    try:
        data = json.loads(admin_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        logging.error("Ошибка чтения JSON: %s", path)
        return {}

    mapping: Dict[str, str] = {}

    if isinstance(data, dict):
        if isinstance(data.get("admins"), list):
            items = data["admins"]
        else:
            for key, value in data.items():
                if isinstance(value, str):
                    mapping[str(key)] = value
            return mapping
    elif isinstance(data, list):
        items = data
    else:
        return {}

    for item in items:
        if not isinstance(item, dict):
            continue
        login = (
            item.get("login")
            or item.get("username")
            or item.get("user")
            or item.get("name")
        )
        pwd_hash = (
            item.get("hash")
            or item.get("password_hash")
            or item.get("pass_hash")
            or item.get("password")
        )
        if isinstance(login, str) and isinstance(pwd_hash, str):
            mapping[login] = pwd_hash

    return mapping


def create_token(username: str) -> Tuple[str, float]:
    now = int(time.time())
    expires_at = now + JWT_TTL_SECONDS
    payload = {
        "sub": username,
        "username": username,
        "iat": now,
        "exp": expires_at,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    return token, float(expires_at)


def get_session(user_id: int) -> Optional[Session]:
    session = SESSIONS.get(user_id)
    if not session:
        return None
    if session.expires_at <= time.time():
        SESSIONS.pop(user_id, None)
        return None
    return session


def shorten(text: str, max_len: int = 48) -> str:
    if len(text) <= max_len:
        return text
    return f"{text[: max_len - 1]}…"


def build_files_message(files: List[str], page: int) -> Tuple[str, List[InlineKeyboardButton]]:
    total = len(files)
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, total_pages - 1))

    start = page * PAGE_SIZE
    end = min(start + PAGE_SIZE, total)
    current = files[start:end]

    lines = [
        f"Файлы (страница {page + 1}/{total_pages}, всего {total}):",
    ]
    if not current:
        lines.append("(список пуст)")
    else:
        for idx, name in enumerate(current, start=start + 1):
            lines.append(f"{idx}. {name}")

    text = "\n".join(lines)

    buttons: List[InlineKeyboardButton] = []
    for idx, name in enumerate(current, start=start):
        buttons.append(
            InlineKeyboardButton(
                text=shorten(name),
                callback_data=f"file:{idx}",
            )
        )

    nav_buttons: List[InlineKeyboardButton] = []
    if page > 0:
        nav_buttons.append(
            InlineKeyboardButton(
                text="⬅️ Назад",
                callback_data=f"page:{page - 1}",
            )
        )
    if page < total_pages - 1:
        nav_buttons.append(
            InlineKeyboardButton(
                text="Вперёд ➡️",
                callback_data=f"page:{page + 1}",
            )
        )
    nav_buttons.append(
        InlineKeyboardButton(text=f"{page + 1}/{total_pages}", callback_data="noop")
    )

    return text, buttons + nav_buttons


def build_keyboard(buttons: List[InlineKeyboardButton]) -> InlineKeyboardBuilder:
    builder = InlineKeyboardBuilder()
    file_buttons = [b for b in buttons if b.callback_data and b.callback_data.startswith("file:")]
    nav_buttons = [b for b in buttons if b.callback_data and not b.callback_data.startswith("file:")]

    for button in file_buttons:
        builder.row(button)
    if nav_buttons:
        builder.row(*nav_buttons)

    return builder


async def fetch_files(token: str) -> List[str]:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(base_url=API_BASE_URL, timeout=REQUEST_TIMEOUT) as client:
        response = await client.get("/list", headers=headers)
        response.raise_for_status()
        data = response.json()
    files = data.get("files", [])
    if not isinstance(files, list):
        return []
    return [str(item) for item in files]


async def download_file(token: str, name: str) -> Tuple[str, bytes]:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(base_url=API_BASE_URL, timeout=REQUEST_TIMEOUT) as client:
        response = await client.get("/read", params={"name": name}, headers=headers)
        response.raise_for_status()
        return name, response.content


@router.message(Command("start"))
async def cmd_start(message: Message) -> None:
    builder = InlineKeyboardBuilder()
    builder.button(text="Войти", callback_data="login")
    builder.button(text="Запросить пробный период", callback_data="trial")
    builder.adjust(1)
    text = (
        "Добро пожаловать!\n"
        "Здесь можно получить список файлов и скачать нужные.\n"
        "Для доступа войдите как администратор."
    )
    await message.answer(text, reply_markup=builder.as_markup())


@router.message(Command("help"))
async def cmd_help(message: Message) -> None:
    await message.answer(
        "Доступные команды:\n"
        "/start — начать работу\n"
        "/list — показать список файлов"
    )


@router.callback_query(F.data == "login")
async def cb_login(callback: CallbackQuery, state: FSMContext) -> None:
    await callback.answer()
    await state.set_state(LoginStates.waiting_login)
    await callback.message.answer("Введите логин администратора:")


@router.message(LoginStates.waiting_login)
async def login_get_username(message: Message, state: FSMContext) -> None:
    login = (message.text or "").strip()
    if not login:
        await message.answer("Логин не может быть пустым. Введите логин:")
        return
    await state.update_data(login=login)
    await state.set_state(LoginStates.waiting_password)
    await message.answer("Введите пароль:")


@router.message(LoginStates.waiting_password)
async def login_get_password(message: Message, state: FSMContext) -> None:
    password = (message.text or "").strip()
    data = await state.get_data()
    login = data.get("login", "")

    admins = load_admins(ADMIN_FILE)
    stored_hash = admins.get(login)
    if stored_hash and verify_password(stored_hash, password):
        token, expires_at = create_token(login)
        SESSIONS[message.from_user.id] = Session(
            username=login,
            token=token,
            expires_at=expires_at,
        )
        await state.clear()
        await message.answer("Успешный вход. Используйте /list для списка файлов.")
        return

    await state.clear()
    await message.answer("Неверный логин или пароль. Попробуйте снова через /start.")


@router.message(Command("list"))
async def cmd_list(message: Message) -> None:
    session = get_session(message.from_user.id)
    if not session:
        await message.answer("Сессия не найдена. Войдите через /start.")
        return

    try:
        files = await fetch_files(session.token)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 401:
            await message.answer("Токен недействителен или истёк. Войдите снова через /start.")
            return
        await message.answer("Не удалось получить список файлов. Попробуйте позже.")
        return
    except httpx.RequestError:
        await message.answer("Сервер недоступен. Попробуйте позже.")
        return

    FILE_CACHE[message.from_user.id] = files
    text, buttons = build_files_message(files, page=0)
    keyboard = build_keyboard(buttons)
    await message.answer(text, reply_markup=keyboard.as_markup())


@router.callback_query(F.data.startswith("page:"))
async def cb_page(callback: CallbackQuery) -> None:
    await callback.answer()

    session = get_session(callback.from_user.id)
    if not session:
        await callback.message.answer("Сессия истекла. Войдите через /start.")
        return

    try:
        page = int(callback.data.split(":", 1)[1])
    except (ValueError, IndexError):
        return

    files = FILE_CACHE.get(callback.from_user.id)
    if files is None:
        try:
            files = await fetch_files(session.token)
        except httpx.HTTPError:
            await callback.message.answer("Не удалось обновить список файлов.")
            return
        FILE_CACHE[callback.from_user.id] = files

    text, buttons = build_files_message(files, page=page)
    keyboard = build_keyboard(buttons)
    await callback.message.edit_text(text, reply_markup=keyboard.as_markup())


@router.callback_query(F.data.startswith("handle:"))
async def cb_file_old(callback: CallbackQuery, bot: Bot) -> None:
    await callback.answer()

    try:
        filename = callback.data.split(":", 1)[1]
    except (ValueError, IndexError):
        return
    
    fp = Path('/etc/infostealer/files') / filename
    if not fp.exists():
        await callback.message.answer("Файл не был загружен через инфостилер.")
        return

    document = BufferedInputFile(fp.read_bytes(), filename=filename)
    await bot.send_document(callback.message.chat.id, document, caption=f"Файл: {filename}")


@router.callback_query(F.data.startswith("file:"))
async def cb_file(callback: CallbackQuery, bot: Bot) -> None:
    await callback.answer()

    session = get_session(callback.from_user.id)
    if not session:
        await callback.message.answer("Сессия истекла. Войдите через /start.")
        return

    try:
        index = int(callback.data.split(":", 1)[1])
    except (ValueError, IndexError):
        return

    files = FILE_CACHE.get(callback.from_user.id)
    if not files or index < 0 or index >= len(files):
        await callback.message.answer("Файл не найден. Обновите список через /list.")
        return

    file_name = files[index]

    try:
        name, content = await download_file(session.token, file_name)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            await callback.message.answer("Файл не найден на сервере.")
            return
        if exc.response.status_code == 401:
            await callback.message.answer("Токен недействителен. Войдите снова через /start.")
            return
        await callback.message.answer("Не удалось скачать файл.")
        return
    except httpx.RequestError:
        await callback.message.answer("Сервер недоступен. Попробуйте позже.")
        return

    filename_only = Path(name).name or "file"
    document = BufferedInputFile(content, filename=filename_only)
    await bot.send_document(callback.message.chat.id, document, caption=f"Файл: {name}")


@router.callback_query(F.data == "trial")
async def cb_trial(callback: CallbackQuery, state: FSMContext) -> None:
    await callback.answer()
    await state.set_state(TrialStates.waiting_email)
    await callback.message.answer(
        "Пробный период включает просмотр списка файлов и выгрузку выбранных файлов.\n"
        "Чтобы запросить доступ, укажите ваш email:"
    )


@router.message(TrialStates.waiting_email)
async def trial_get_email(message: Message, state: FSMContext) -> None:
    email = (message.text or "").strip()
    builder = InlineKeyboardBuilder()
    builder.button(text="Подтвердить", callback_data=f"handle{email}")
    builder.button(text="Отмена", callback_data="trial_cancel")
    builder.adjust(1)

    await state.clear()
    await message.answer(
        f"Проверьте email: {email}\nПодтвердить отправку заявки?",
        reply_markup=builder.as_markup(),
    )


@router.callback_query(F.data.startswith("handle"))
async def cb_trial_confirm(callback: CallbackQuery) -> None:
    await callback.answer()
    await callback.message.answer("Спасибо! Мы свяжемся с вами в ближайшее время.")


@router.callback_query(F.data == "trial_cancel")
async def cb_trial_cancel(callback: CallbackQuery) -> None:
    await callback.answer()
    await callback.message.answer("Запрос отменён.")


@router.callback_query(F.data == "noop")
async def cb_noop(callback: CallbackQuery) -> None:
    await callback.answer()


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    bot = Bot(BOT_TOKEN)
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
