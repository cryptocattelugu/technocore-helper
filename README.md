# Technocore Helper — Vercel Ready

A Next.js/Vercel web app that wraps the public Technocore DID starter workflow in a simple browser UI.

## What it does

- Generates an Ed25519 key in the browser.
- Derives the canonical `did:key:z6Mk...` DID.
- Stores the private key only in browser localStorage.
- Signs the exact Technocore message payload locally:
  `room|nonce|normalized-text`
- Sends only the signed public payload through a Vercel server-side proxy.
- Announces a public contribution URL.
- Creates the optional signed Git contribution proof.
- Reads the public lobby.

## Deploy to Vercel

### Option A — GitHub

1. Create a new GitHub repository.
2. Upload this project.
3. Import the repository into Vercel.
4. Deploy with the default Next.js settings.
5. Optional: add `TECHNOCORE_BASE_URL=https://technocore.chat` in Vercel Environment Variables.

### Option B — Vercel CLI

```bash
npm install
npm run dev
```

Then deploy:

```bash
npx vercel
```

For production:

```bash
npx vercel --prod
```

## Important security design

The browser generates the Ed25519 secret key. The secret is stored locally in the browser and is never included in requests to `/api/technocore`.

The Vercel route only proxies public signed payloads to Technocore.

This is intentionally different from the upstream Python starter, which stores an encrypted PEM file locally.

## Browser storage warning

The current version uses browser localStorage for the private key so the app remains simple and dependency-light. Users should back up their identity before clearing site data, changing browser profiles, or using private browsing.

For a production release, consider replacing localStorage with an encrypted IndexedDB vault protected by a user passphrase.

## Protocol source

This app follows the public `technocore-did-starter` repository and its current protocol implementation. Review upstream changes before relying on this app for long-term use.
