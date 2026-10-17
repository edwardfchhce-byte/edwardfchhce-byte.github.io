# Mars Construct Multiplayer Beta

This build adds server-backed accounts, persistent colony saves, and online player/colony presence to Mars Construct.

## Run locally

1. Install Node.js 20 or newer.
2. Open a terminal in this folder.
3. Run `npm install`.
4. Run `npm start`.
5. Open `http://localhost:3000` (not the HTML file directly).

By default, accounts and saves are stored in `../mars_construct_data/accounts.json` (outside the public website folder). Back up this file. Do not commit it to a public repository.

## Deploy online

Deploy this folder to a Node.js host that supports persistent disk storage (for example, a Render web service with a persistent disk). Set the start command to `npm start`, Node version to 20+, and set `NODE_ENV=production`. Mount a persistent disk and set `DATA_DIR` to its mount path, e.g. `/var/data`. Without persistent disk storage, accounts and saves may be lost when the host replaces its filesystem.

GitHub Pages cannot run `server.js`; use the Node host URL for the online game, or configure a custom domain/reverse proxy. Keep the game and API on the same origin so the secure HttpOnly login cookie works.

## Current multiplayer scope

- Account registration/login with salted scrypt password hashes; passwords are never stored as plain text.
- HttpOnly, SameSite session cookie with a 30-day lifetime.
- Server-side saved resources, buildings, soldiers, research completions, and tutorial progress; autosaves every 15 seconds.
- Online player roster and a visual preview of other online players' colonies.

This is an early multiplayer beta. Players currently have their own saved simulation and can see each other's online colony previews. Shared authoritative world simulation, player-vs-player attacks, shared resource trading, and anti-cheat validation are not implemented yet. Do not use this prototype to store sensitive information.
