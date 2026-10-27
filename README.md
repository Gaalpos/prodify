# Prodify

Notes, journal, reflection questions, tasks, projects, habits and calendar, as a Linux desktop app built with Tauri 2.

## Where your data lives

- **Your content**: plain Markdown files in `~/Prodify` (`notes/`, `archive/`, `templates/`, `lists/`, `collections/`, `journal/`, `attachments/` for journal photos, `projects/`, `habits/`, `tasks.md`, `events.md`, `questions.md`). You can open, edit, back up or sync that folder with other tools. Edits made outside the app show up the next time you open it.
- **Note properties** (`created`, `tags`, `categories` and any you add) are stored as YAML front matter in the same format Obsidian uses, with categories written as `"[[Name]]"` links, so the notes folder can be opened in Obsidian too.
- **Settings**: `~/.config/io.prodify.app/settings.json`.

## Exercises

The gym tracker suggests exercises in English or Spanish from a catalogue bundled in `src/exercises.js`, so it works offline. Exercises it doesn't have are looked up live on wger. The data comes from [free-exercise-db](https://github.com/yuhonas/free-exercise-db), which is public domain (Unlicense), and from [wger](https://wger.de), licensed CC BY-SA 4.0. Exercise photos load from those sites when you're online. The full credits are in `src/EXERCISES-LICENSE.txt`.

## Collections

Books, movies, series, anime and games are Markdown files in `collections/<type>/`. Metadata comes from Open Library, TVmaze and AniList (no key needed) and from TMDB (movies) and RAWG (games), which need a free API key set in Settings → Collections. This product uses the TMDB API but is not endorsed or certified by TMDB.

## Layout

- `src/`: the app itself (`index.html`, `styles.css`, `app.js`, bundled fonts). `boot.js` loads your files before the app starts. Opened as a plain web page, it still works and saves to the browser instead.
- `src-tauri/`: the native side. `src/lib.rs` reads and writes the Markdown folder and settings, and handles the save dialog, reminder notifications and "Open folder".
- `app-icon.svg`: the source for the icons in `src-tauri/icons/` (regenerate with `npx tauri icon app-icon.svg`).

## One-time setup (Linux Mint / Ubuntu)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install libwebkit2gtk-4.1-dev libxdo-dev libayatana-appindicator3-dev librsvg2-dev
npm install
```

## Run while developing

```bash
npm run dev
```

## Build the .deb

```bash
npm run tauri build
```

The package lands in `src-tauri/target/release/bundle/deb/`.

## Notes

- AI-generated questions relied on the Claude artifact runtime, which isn't available in the desktop app, so new questions come from the built-in list.
- Reminders only fire while the app is open.
