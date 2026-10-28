# Reference bot: admins by numeric id, escaped HTML, webhook secret, checked pre-checkout.
import os
from aiogram import Bot, Dispatcher, F, html
from aiogram.types import Message, PreCheckoutQuery

from .orders import find_order

bot = Bot(os.environ["BOT_TOKEN"])
dp = Dispatcher()
ADMIN_IDS = {int(x) for x in os.environ["ADMIN_IDS"].split(",")}
WEBHOOK_URL = os.environ["WEBHOOK_URL"]
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"]


@dp.message(F.text == "/start")
async def start(message: Message):
    await message.answer(f"Salom, <b>{html.quote(message.from_user.first_name)}</b>!", parse_mode="HTML")


@dp.message(F.text == "/stats")
async def stats(message: Message):
    if message.from_user.id in ADMIN_IDS:
        await message.answer("orders today: 42")


@dp.pre_checkout_query()
async def pre_checkout(query: PreCheckoutQuery):
    order = await find_order(query.invoice_payload)
    ok = order is not None and order.amount == query.total_amount and order.currency == query.currency
    await query.answer(ok=ok, error_message=None if ok else "Order expired, please try again.")


async def on_startup():
    await bot.set_webhook(WEBHOOK_URL, secret_token=WEBHOOK_SECRET)
