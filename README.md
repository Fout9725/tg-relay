# tg-relay
Node WebSocket <-> raw TCP relay for Telegram MTProto egress (GitHub Codespaces).
```sh
npm install
PORT=8000 node server.js
```
Endpoints:
- `/ws?host=<ip>&port=<n>` — raw relay
- `/apiws?dst=<ip>&dc=<n>` — Telegram DC relay
- `/tgchk?dc=<ip>&port=<n>[&mtp=abr][&t=<ms>]` — MTProto egress probe