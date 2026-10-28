# Payments (Telegram Stars, provider payments, external checkouts)

Telegram payments follow one flow: the bot creates an invoice → the user pays in the
Telegram UI → the bot receives `pre_checkout_query` (answer within 10 seconds) → the bot
receives a message with `successful_payment`. Only the last step proves money moved.

## Checklist

- [ ] Purchases are granted **only** when the bot receives `successful_payment`
- [ ] The grant is idempotent: keyed on `telegram_payment_charge_id`, safe to receive twice
- [ ] `invoice_payload` identifies a server-side order; amount and currency are checked
      against it in `pre_checkout_query` and again on `successful_payment`
- [ ] `pre_checkout_query` is answered `ok=False` when the order is gone, stock is out or the price changed
- [ ] Prices come from the server, never from the Mini App request that creates the invoice
- [ ] Refunds (`refundStarPayment`) revoke what was granted
- [ ] External checkouts (Payme, Click, Uzum, Stripe) are confirmed by the provider's
      server-to-server callback with its signature verified, not by a redirect or the Mini App

## Grant on successful_payment only

The Mini App's `Telegram.WebApp.openInvoice(url, callback)` callback receives
`paid | cancelled | failed | pending`. It runs in the user's browser, so it can be called by
hand from DevTools. Using it to unlock content, add credits or mark an order paid is a
**high** finding (free purchases for anyone who opens the console).

```js
// ❌
tg.openInvoice(link, (status) => { if (status === 'paid') api('/api/unlock'); });
// ✅ the server grants on successful_payment; the client just refreshes
tg.openInvoice(link, () => refreshBalance());
```

Also check the server endpoint the callback calls: `/api/unlock` with no payment record
behind it is the same bug one layer down.

## Validate the pre-checkout query

`pre_checkout_query` contains `invoice_payload`, `currency` and `total_amount`. A handler
that answers `ok=True` without looking them up lets the user pay for an order that no
longer exists, at a stale price, or twice. On its own this is **low** (money is taken, the
grant logic decides the impact); it becomes **medium/high** when the grant on
`successful_payment` also trusts the payload without a server-side order.

```python
order = await find_order(query.invoice_payload)
ok = order is not None and order.amount == query.total_amount and order.currency == query.currency
await query.answer(ok=ok, error_message=None if ok else "Order expired, please try again.")
```

Payloads are set by your bot when it creates the invoice, but invoice links can be shared
and replayed. Treat the payload as an id to look up, not as data to trust.

## Telegram Stars notes

- Currency `XTR`, amounts are whole Stars, no provider token.
- Digital goods sold inside Telegram must use Stars; physical goods may use providers.
- `refundStarPayment(user_id, telegram_payment_charge_id)` exists, so make sure a
  refund path (or a support refund) revokes the purchase.
