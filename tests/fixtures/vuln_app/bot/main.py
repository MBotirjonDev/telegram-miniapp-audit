# Intentionally vulnerable Telegram bot used by the test suite. Do not copy.
import os
from aiogram import Bot, Dispatcher, F
from aiogram.types import Message, PreCheckoutQuery

bot = Bot(os.environ["BOT_TOKEN"])
dp = Dispatcher()
WEBHOOK_URL = "https://shop.example.uz/tg/webhook"


@dp.message(F.text == "/start")
async def start(message: Message):
    await message.answer(f"Salom, <b>{message.from_user.first_name}</b>!", parse_mode="HTML")


@dp.message(F.text == "/stats")
async def stats(message: Message):
    if message.from_user.username == "shop_admin":
        await message.answer("orders today: 42")


@dp.pre_checkout_query()
async def pre_checkout(query: PreCheckoutQuery):
    await bot.answer_pre_checkout_query(query.id, ok=True)


async def on_startup():
    await bot.set_webhook(WEBHOOK_URL)
