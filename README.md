# ScanWEBCheckBug

Passive web fingerprint scanner for security lab and CTF-style use.

## Stack

- Frontend: React + Vite
- Backend API: Node.js + Express
- Queue: BullMQ + Redis
- Scanner worker: Python
- Realtime progress: Socket.IO
- DB target: PostgreSQL with Prisma config, not used for persistence yet
- Deploy: Docker Compose

## Local Run

Requirements:

- Node.js 20+
- Redis 6.2+ recommended
- Python 3 available as `python`, `python3`, or via `PYTHON_BIN`

Commands:

```bash
npm install
npm run api
npm run worker
npm run dev:web
```

Open:

- Web: http://localhost:5173
- API health: http://localhost:4000/api/health

## Docker

```bash
docker compose up --build
```

Open http://localhost:5173.

Postgres and Redis are internal Docker services by default. They are not exposed
on the host server, so existing services on host ports `5432` or `6379` will not
conflict.

This project intentionally uses one tracked `.env` file for deployment config.
Update `.env`, commit it, then deploy.

To run the web on a different server port, edit `.env`:

```bash
WEB_PORT=8081
API_PORT=4000
VITE_API_BASE_URL=http://YOUR_SERVER_IP:4000
CORS_ORIGIN=http://YOUR_SERVER_IP:8081
```

Then redeploy:

```bash
./Deploy.sh
```

By default `Deploy.sh` skips `docker compose pull` to keep deploys faster on
slow servers. To refresh base images too:

```bash
PULL_IMAGES=true ./Deploy.sh
```

## Scanner Notes

The scanner infers backend language and database from public signals only:

- HTTP headers
- cookies
- HTML meta generator tags
- framework/CMS asset paths
- public database error strings if already exposed by the target

Database detection is usually weak because a database is normally hidden behind
the backend. Results include confidence and evidence instead of claiming
certainty.

Private, loopback, link-local, and reserved targets are blocked by default.
For an authorized local lab only, set:

```bash
ALLOW_PRIVATE_TARGETS=true
```
