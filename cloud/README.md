# Prodify Cloud

The sync server behind Prodify Plus: a Cloudflare Worker with a D1 database (users, sign-in codes, sessions, the object index) and an R2 bucket (the objects themselves).

The app encrypts everything before it uploads it, including file names. The server only ever stores scrambled bytes and can't read anyone's notes.

## Plans

| Plan | Storage | |
|---|---|---|
| Free | 100 MB | Everyone who signs in |
| Basic | 5 GB | Set by hand for now (payments come later) |
| Pro | 50 GB | Set by hand for now |

The limits are `PLANS` in `src/worker.js`. A single object can be up to 25 MB.

## Run it locally

```bash
cd cloud
npm install
npm run db:local
npm run dev
```

The server runs on `http://localhost:8787`. In the app, open Settings → Account and data → Prodify Cloud → Server and enter that address.

`.dev.vars` sets `DEV=1`, so sign-in codes are shown in the app instead of being emailed.

## Put it on your Cloudflare account

1. Create a free Cloudflare account, then sign in from this folder: `npx wrangler login`.
2. Create the database: `npx wrangler d1 create prodify-cloud`. Copy the `database_id` it prints into `wrangler.toml`.
3. Create the storage bucket: `npx wrangler r2 bucket create prodify-cloud`. R2 has to be enabled once in the Cloudflare dashboard. It's free up to 10 GB.
4. Set up the tables: `npm run db:remote`.
5. Email for sign-in codes:
   1. Create a free [Resend](https://resend.com) account (3,000 emails a month) and verify a domain you own.
   2. Set `MAIL_FROM` in `wrangler.toml` to an address on that domain, for example `Prodify <login@yourdomain.com>`.
   3. Then run `npx wrangler secret put RESEND_API_KEY`.
6. Admin secret, for changing plans by hand: `npx wrangler secret put ADMIN_SECRET`. Use a long random value.
7. Deploy: `npm run deploy`. Wrangler prints the address, for example `https://prodify-cloud.<you>.workers.dev`.
8. In the app, put that address in `CLOUD_DEFAULT` in `src/app.js`, so users don't have to enter it. If you use your own domain instead of `workers.dev`, also add it to `connect-src` in `src-tauri/tauri.conf.json`.

## Change someone's plan

```bash
curl -X POST https://prodify-cloud.<you>.workers.dev/admin/plan \
  -H "x-admin-secret: <your admin secret>" -H "content-type: application/json" \
  -d '{"email":"someone@example.com","plan":"basic"}'
```

## How sync works

- **Objects.** Each user's data is a set of objects:
  - `account`: the account file. It holds the data key, locked with the password and the recovery key, and nothing secret.
  - `r/<hash>`: one note, task list and so on. The hash comes from the file name and the data key. The content is the encrypted name and text.
  - `a/<name>`: one photo or PDF, encrypted.
- **Revisions.** Every change bumps the object's revision and the user's sequence number.
- **Pulling.** Devices ask for `GET /changes?since=<seq>`, then download what changed. They merge it line by line, starting from the last synced version.
- **Pushing.** Devices upload with `If-Match: <revision they last saw>`. If another device changed the object in between, the server answers 409. The device then pulls, merges and tries again, so nothing is overwritten.
- **Deletes.** A delete leaves a marker, so other devices delete the object too.
