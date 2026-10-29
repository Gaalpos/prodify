use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_opener::OpenerExt;

/// The app's notes, journal, tasks, projects and habits live as Markdown files in a folder
/// (~/Prodify unless another one was chosen in Settings → Storage), so they can be read,
/// edited or synced with other tools.
fn default_root(app: &AppHandle) -> Result<PathBuf, String> {
    // On phones the files live in the app's own storage.
    #[cfg(mobile)]
    return Ok(app.path().app_data_dir().map_err(|e| e.to_string())?.join("Prodify"));
    #[cfg(desktop)]
    Ok(app.path().home_dir().map_err(|e| e.to_string())?.join("Prodify"))
}

/// Holds the chosen folder's path; no file (or an empty one) means the default folder.
fn folder_choice_file(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("data-folder.txt"))
}

fn files_root(app: &AppHandle) -> Result<PathBuf, String> {
    let chosen = fs::read_to_string(folder_choice_file(app)?)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let root = match chosen {
        Some(p) => p,
        None => default_root(app)?,
    };
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    Ok(root)
}

/// Settings and other small app state: ~/.config/<identifier>/settings.json.
fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("settings.json"))
}

static SETTINGS_LOCK: Mutex<()> = Mutex::new(());

/// Writes to a hidden temp file next to the target, flushes it, then renames it
/// over the target, so a crash mid-save never leaves a half-written file.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let name = path.file_name().ok_or("Invalid file name")?.to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.tmp"));
    let mut f = File::create(&tmp).map_err(|e| e.to_string())?;
    f.write_all(data).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// Turns an app file key like "notes/2026-10-19-1200.md" into a path inside
/// the root, refusing anything that could escape it or isn't Markdown.
fn file_path(root: &Path, key: &str) -> Result<PathBuf, String> {
    let rel = Path::new(key);
    let ok = key.ends_with(".md") && rel.components().all(|c| matches!(c, Component::Normal(_)));
    if !ok {
        return Err(format!("Refusing to use file name {key:?}"));
    }
    Ok(root.join(rel))
}

/// Collects every .md file under `dir`, keyed by its path relative to `root`
/// with "/" separators. Hidden entries, symlinks and non-UTF-8 files are skipped.
fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, String>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_dir() {
            walk(root, &path, out)?;
        } else if kind.is_file() && name.ends_with(".md") {
            if let Ok(text) = fs::read_to_string(&path) {
                let key = path
                    .strip_prefix(root)
                    .map_err(|e| e.to_string())?
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                out.insert(key, text.replace("\r\n", "\n"));
            }
        }
    }
    Ok(())
}

fn read_settings(path: &Path) -> Result<BTreeMap<String, String>, String> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("{} is damaged ({e})", path.display()))
}

/* ---------- app storage (SQLite) ----------
   Settings → Data and backups can keep everything in a private database instead of the Markdown folder: the same
   files (key → text, which the app may encrypt, names included), attachments as blobs, and the automatic backups.
   Each data folder gets its own database in the app's data directory (so every user keeps their own), and
   storage.json in the config directory lists the folders that use one. The commands below keep working the same in
   both modes, so the app only needs to know which mode is on. */
fn es(e: rusqlite::Error) -> String {
    e.to_string()
}

fn storage_file(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("storage.json"))
}

fn storage_modes(app: &AppHandle) -> Result<BTreeMap<String, String>, String> {
    read_settings(&storage_file(app)?)
}

fn storage_save(app: &AppHandle, modes: &BTreeMap<String, String>) -> Result<(), String> {
    let text = serde_json::to_string_pretty(modes).map_err(|e| e.to_string())?;
    write_atomic(&storage_file(app)?, text.as_bytes())
}

/// FNV-1a: a stable hash of the folder path for the database's file name.
fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn db_file(app: &AppHandle, root: &Path) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?.join("databases");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join(format!("prodify-{:016x}.db", fnv(&root.to_string_lossy()))))
}

/// The database of the current folder when it uses app storage; None for the Markdown folder.
fn db_for(app: &AppHandle) -> Result<Option<PathBuf>, String> {
    let root = files_root(app)?;
    let key = root.to_string_lossy().into_owned();
    let on = storage_modes(app)?.get(&key).is_some_and(|m| m.as_str() == "db");
    if on {
        Ok(Some(db_file(app, &root)?))
    } else {
        Ok(None)
    }
}

static DB: Mutex<Option<(PathBuf, Connection)>> = Mutex::new(None);

/// Runs `f` on the open database at `path`, opening (and creating) it first if needed.
fn with_db<T>(path: &Path, f: impl FnOnce(&mut Connection) -> Result<T, String>) -> Result<T, String> {
    let mut guard = DB.lock().map_err(|e| e.to_string())?;
    if guard.as_ref().map(|(p, _)| p.as_path() != path).unwrap_or(true) {
        let c = Connection::open(path).map_err(es)?;
        c.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS files (key TEXT PRIMARY KEY, body TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS attachments (name TEXT PRIMARY KEY, data BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS backups (name TEXT PRIMARY KEY, data TEXT NOT NULL);",
        )
        .map_err(es)?;
        *guard = Some((path.to_path_buf(), c));
    }
    let (_, c) = guard.as_mut().ok_or("The database isn't open")?;
    f(c)
}

/// Keys in the database can be any text the app uses (encrypted names look like "enc/<hash>").
fn db_key_ok(key: &str) -> bool {
    !key.is_empty() && key.len() < 4096 && !key.contains('\0')
}

fn db_attachment(path: &Path, name: &str) -> Result<Option<Vec<u8>>, String> {
    with_db(path, |c| {
        c.query_row("SELECT data FROM attachments WHERE name = ?1", params![name], |r| r.get::<_, Vec<u8>>(0))
            .optional()
            .map_err(es)
    })
}

fn db_put_attachment(path: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    with_db(path, |c| {
        c.execute("INSERT OR REPLACE INTO attachments (name, data) VALUES (?1, ?2)", params![name, bytes])
            .map(|_| ())
            .map_err(es)
    })
}

#[derive(Serialize)]
struct Boot {
    dir: String,
    default_dir: String,
    files: BTreeMap<String, String>,
    kv: BTreeMap<String, String>,
    /// "md" for the Markdown folder, "db" for app storage.
    storage: String,
}

#[tauri::command]
async fn load_all(app: AppHandle) -> Result<Boot, String> {
    let root = files_root(&app)?;
    let db = db_for(&app)?;
    let mut files = BTreeMap::new();
    match &db {
        Some(path) => with_db(path, |c| {
            let mut st = c.prepare("SELECT key, body FROM files").map_err(es)?;
            let rows = st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map_err(es)?;
            for row in rows {
                let (k, v) = row.map_err(es)?;
                files.insert(k, v);
            }
            Ok(())
        })?,
        None => walk(&root, &root, &mut files)?,
    }
    let kv = read_settings(&settings_path(&app)?)?;
    let default_dir = default_root(&app)?.to_string_lossy().into_owned();
    let storage = if db.is_some() { "db" } else { "md" }.to_string();
    Ok(Boot { dir: root.to_string_lossy().into_owned(), default_dir, files, kv, storage })
}

/// Applies a batch of changes: writes changed files, deletes removed ones,
/// then tidies up folders the deletions left empty.
#[tauri::command]
async fn sync_files(
    app: AppHandle,
    write: BTreeMap<String, String>,
    remove: Vec<String>,
) -> Result<(), String> {
    if let Some(path) = db_for(&app)? {
        if let Some(bad) = write.keys().chain(remove.iter()).find(|k| !db_key_ok(k)) {
            return Err(format!("Refusing to use file name {bad:?}"));
        }
        return with_db(&path, |c| {
            let tx = c.transaction().map_err(es)?;
            for (k, v) in &write {
                tx.execute("INSERT OR REPLACE INTO files (key, body) VALUES (?1, ?2)", params![k, v]).map_err(es)?;
            }
            for k in &remove {
                tx.execute("DELETE FROM files WHERE key = ?1", params![k]).map_err(es)?;
            }
            tx.commit().map_err(es)
        });
    }
    let root = files_root(&app)?;
    let writes = write
        .iter()
        .map(|(k, v)| file_path(&root, k).map(|p| (p, v)))
        .collect::<Result<Vec<_>, _>>()?;
    let removes = remove.iter().map(|k| file_path(&root, k)).collect::<Result<Vec<_>, _>>()?;
    for (path, text) in writes {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        write_atomic(&path, text.as_bytes())?;
    }
    for path in removes {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("Could not delete {}: {e}", path.display())),
        }
        let mut dir = path.parent();
        while let Some(d) = dir {
            if d == root || fs::remove_dir(d).is_err() {
                break;
            }
            dir = d.parent();
        }
    }
    Ok(())
}

/// Stores one settings value; None deletes it.
#[tauri::command]
async fn kv_set(app: AppHandle, key: String, value: Option<String>) -> Result<(), String> {
    let _guard = SETTINGS_LOCK.lock().map_err(|e| e.to_string())?;
    let path = settings_path(&app)?;
    let mut kv = read_settings(&path)?;
    match value {
        Some(v) => kv.insert(key, v),
        None => kv.remove(&key),
    };
    let text = serde_json::to_string_pretty(&kv).map_err(|e| e.to_string())?;
    write_atomic(&path, text.as_bytes())
}

/// Asks where to save a download, then writes the base64-encoded bytes there.
/// Returns false when the person cancels the dialog.
#[tauri::command]
async fn save_download(app: AppHandle, name: String, data: String) -> Result<bool, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| e.to_string())?;
    let mut dialog = app.dialog().file().set_title("Save file").set_file_name(&name);
    if let Some(ext) = Path::new(&name).extension().and_then(|e| e.to_str()) {
        dialog = dialog.add_filter(ext.to_uppercase(), &[ext]);
    }
    let Some(file) = dialog.blocking_save_file() else {
        return Ok(false);
    };
    let path = file.into_path().map_err(|e| e.to_string())?;
    write_atomic(&path, &bytes)?;
    Ok(true)
}

/// Saves a journal photo (base64 JPEG) as ~/Prodify/attachments/<name>.
/// Names are generated by the app; anything else is refused.
#[tauri::command]
async fn save_attachment(app: AppHandle, name: String, data: String) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() < 200
        && !name.starts_with('.')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
    if !ok {
        return Err(format!("Refusing to use attachment name {name:?}"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| e.to_string())?;
    if let Some(path) = db_for(&app)? {
        return db_put_attachment(&path, &name, &bytes);
    }
    let dir = files_root(&app)?.join("attachments");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    write_atomic(&dir.join(name), &bytes)
}

/// Downloads an image (a collection cover) into attachments/ as `<base>.<ext>` and returns the file name.
/// Done here rather than in the window because some image hosts don't allow web pages to fetch their files.
#[tauri::command]
async fn download_attachment(app: AppHandle, url: String, base: String) -> Result<String, String> {
    if !url.starts_with("https://") {
        return Err("Only https images can be downloaded".into());
    }
    let ok = !base.is_empty()
        && base.len() < 150
        && !base.starts_with('.')
        && base.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
    if !ok {
        return Err(format!("Refusing to use attachment name {base:?}"));
    }
    let dir = files_root(&app)?.join("attachments");
    let db = db_for(&app)?;
    tauri::async_runtime::spawn_blocking(move || {
        const MAX: u64 = 20 * 1024 * 1024;
        let resp = ureq::get(&url)
            .timeout(std::time::Duration::from_secs(30))
            .call()
            .map_err(|e| e.to_string())?;
        let ext = match resp.content_type() {
            "image/jpeg" | "image/jpg" => "jpg",
            "image/png" => "png",
            "image/webp" => "webp",
            "image/gif" => "gif",
            other => return Err(format!("Not an image ({other})")),
        };
        let mut bytes = Vec::new();
        resp.into_reader()
            .take(MAX + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX {
            return Err("The image is too large".into());
        }
        let name = format!("{base}.{ext}");
        if let Some(path) = &db {
            db_put_attachment(path, &name, &bytes)?;
            return Ok(name);
        }
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        write_atomic(&dir.join(&name), &bytes)?;
        Ok(name)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Copies a stored attachment (a Storage image or PDF) to a place the person picks in a save dialog.
/// Returns false when the dialog is cancelled.
#[tauri::command]
async fn export_attachment(app: AppHandle, name: String, save_as: String) -> Result<bool, String> {
    let ok = !name.is_empty()
        && name.len() < 200
        && !name.starts_with('.')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
    if !ok {
        return Err(format!("Refusing to export attachment {name:?}"));
    }
    let stored = match db_for(&app)? {
        Some(path) => Some(db_attachment(&path, &name)?.ok_or("That file is missing from attachments")?),
        None => None,
    };
    let src = files_root(&app)?.join("attachments").join(&name);
    if stored.is_none() && !src.is_file() {
        return Err("That file is missing from attachments".into());
    }
    let mut dialog = app.dialog().file().set_title("Save file").set_file_name(&save_as);
    if let Some(ext) = Path::new(&save_as).extension().and_then(|e| e.to_str()) {
        dialog = dialog.add_filter(ext.to_uppercase(), &[ext]);
    }
    let Some(file) = dialog.blocking_save_file() else {
        return Ok(false);
    };
    let path = file.into_path().map_err(|e| e.to_string())?;
    match stored {
        Some(bytes) => write_atomic(&path, &bytes)?,
        None => {
            fs::copy(&src, &path).map_err(|e| e.to_string())?;
        }
    }
    Ok(true)
}

/// Opens a stored attachment (a PDF from the Storage section) with the system's default app.
fn attachment_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 200
        && !name.starts_with('.')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

/// Reads one file from attachments/ as base64, so the app can decrypt it (encrypted accounts).
#[tauri::command]
async fn read_attachment(app: AppHandle, name: String) -> Result<String, String> {
    if !attachment_name_ok(&name) {
        return Err(format!("Refusing to read attachment {name:?}"));
    }
    let bytes = match db_for(&app)? {
        Some(path) => db_attachment(&path, &name)?.ok_or("That file is missing from attachments")?,
        None => fs::read(files_root(&app)?.join("attachments").join(&name)).map_err(|e| e.to_string())?,
    };
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Names of the files in attachments/ (hidden ones skipped), for encrypting or decrypting all of them.
#[tauri::command]
async fn list_attachments(app: AppHandle) -> Result<Vec<String>, String> {
    if let Some(path) = db_for(&app)? {
        return with_db(&path, |c| {
            let mut st = c.prepare("SELECT name FROM attachments ORDER BY name").map_err(es)?;
            let rows = st.query_map([], |r| r.get::<_, String>(0)).map_err(es)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(es)
        });
    }
    let dir = files_root(&app)?.join("attachments");
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut names: Vec<String> = fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| attachment_name_ok(n))
        .collect();
    names.sort();
    Ok(names)
}

/// Where decrypted copies of encrypted attachments go to be opened in another app; emptied when Prodify starts.
fn open_temp_dir(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app.path().app_cache_dir().map_err(|e| e.to_string())?.join("open"))
}

/// Opens a decrypted copy of an encrypted attachment (a PDF) in the default app.
#[tauri::command]
async fn open_temp_file(app: AppHandle, name: String, data: String) -> Result<(), String> {
    if !attachment_name_ok(&name) {
        return Err(format!("Refusing to open {name:?}"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| e.to_string())?;
    open_bytes(&app, &name, &bytes)
}

/// Writes `bytes` to the temporary folder and opens the file in the default app.
fn open_bytes(app: &AppHandle, name: &str, bytes: &[u8]) -> Result<(), String> {
    let dir = open_temp_dir(app)?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(name);
    write_atomic(&path, bytes)?;
    app.opener()
        .open_path(path.to_string_lossy(), None::<&str>)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn open_attachment(app: AppHandle, name: String) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() < 200
        && !name.starts_with('.')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
    if !ok {
        return Err(format!("Refusing to open attachment {name:?}"));
    }
    if let Some(path) = db_for(&app)? {
        let bytes = db_attachment(&path, &name)?.ok_or("That file is missing from attachments")?;
        return open_bytes(&app, &name, &bytes);
    }
    let path = files_root(&app)?.join("attachments").join(&name);
    app.opener()
        .open_path(path.to_string_lossy(), None::<&str>)
        .map_err(|e| e.to_string())
}

/// Reads a web page's title and description for a saved link (only the first 512 KB of the page).
#[tauri::command]
async fn link_info(url: String) -> Result<(String, String), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("Only web links can be read".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let resp = ureq::get(&url)
            .timeout(std::time::Duration::from_secs(15))
            .call()
            .map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        resp.into_reader()
            .take(512 * 1024)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        let html = String::from_utf8_lossy(&bytes).to_string();
        let title = page_meta(&html, "og:title")
            .or_else(|| page_title(&html))
            .unwrap_or_default();
        let desc = page_meta(&html, "og:description")
            .or_else(|| page_meta(&html, "description"))
            .unwrap_or_default();
        Ok((title, desc))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The content of a <meta> tag whose property or name is `key` (in quotes, either attribute order).
fn page_meta(html: &str, key: &str) -> Option<String> {
    let low = html.to_ascii_lowercase();
    let (dq, sq) = (format!("\"{key}\""), format!("'{key}'"));
    let mut from = 0;
    while let Some(i) = low[from..].find("<meta") {
        let start = from + i;
        let end = match low[start..].find('>') {
            Some(e) => start + e,
            None => break,
        };
        let tag = &low[start..end];
        if tag.contains(&dq) || tag.contains(&sq) {
            if let Some(v) = tag_attr(&html[start..end], "content") {
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
        from = end;
    }
    None
}

/// The text of the page's <title>.
fn page_title(html: &str) -> Option<String> {
    let low = html.to_ascii_lowercase();
    let i = low.find("<title")?;
    let s = i + low[i..].find('>')? + 1;
    let e = s + low[s..].find("</title")?;
    let t = html_text(&html[s..e]);
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

/// A quoted attribute value from a tag.
fn tag_attr(tag: &str, name: &str) -> Option<String> {
    let low = tag.to_ascii_lowercase();
    let key = format!(" {name}=");
    let i = low.find(&key)? + key.len();
    let rest = &tag[i..];
    let q = rest.chars().next()?;
    if q != '"' && q != '\'' {
        return None;
    }
    let body = &rest[1..];
    let j = body.find(q)?;
    Some(html_text(&body[..j]))
}

/// Decodes the common HTML entities and collapses whitespace.
fn html_text(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Sends one prompt to Claude through the Anthropic Messages API with the person's own key and returns the reply text.
/// Done here rather than in the window so the key and request never depend on the page's network rules.
#[tauri::command]
async fn ai_complete(
    key: String,
    model: String,
    prompt: String,
    system: Option<String>,
    max_tokens: Option<u32>,
) -> Result<String, String> {
    let key = key.trim().to_string();
    if key.is_empty() {
        return Err("Add your Anthropic API key in Settings".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let mut body = serde_json::json!({
            "model": model,
            "max_tokens": max_tokens.unwrap_or(1024),
            "messages": [{ "role": "user", "content": prompt }]
        });
        if let Some(s) = system.filter(|s| !s.is_empty()) {
            body["system"] = serde_json::Value::String(s);
        }
        let resp = ureq::post("https://api.anthropic.com/v1/messages")
            .timeout(std::time::Duration::from_secs(90))
            .set("x-api-key", &key)
            .set("anthropic-version", "2023-06-01")
            .set("content-type", "application/json")
            .send_string(&body.to_string());
        let text = match resp {
            Ok(r) => r.into_string().map_err(|e| e.to_string())?,
            Err(ureq::Error::Status(code, r)) => {
                let t = r.into_string().unwrap_or_default();
                let msg = serde_json::from_str::<serde_json::Value>(&t)
                    .ok()
                    .and_then(|v| v["error"]["message"].as_str().map(String::from))
                    .unwrap_or(t);
                return Err(format!("The AI request failed ({code}): {msg}"));
            }
            Err(e) => return Err(e.to_string()),
        };
        let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        let out = v["content"]
            .as_array()
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| p["text"].as_str())
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        Ok(out)
    })
    .await
    .map_err(|e| e.to_string())?
}

fn backup_name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() < 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c))
}

/// Saves a backup (a JSON snapshot of every file) as <folder>/.prodify-backups/<name>.json, keeping the newest 7.
#[tauri::command]
async fn backup_write(app: AppHandle, name: String, data: String) -> Result<(), String> {
    if !backup_name_ok(&name) {
        return Err(format!("Refusing to use backup name {name:?}"));
    }
    if let Some(path) = db_for(&app)? {
        return with_db(&path, |c| {
            c.execute("INSERT OR REPLACE INTO backups (name, data) VALUES (?1, ?2)", params![name, data]).map_err(es)?;
            c.execute("DELETE FROM backups WHERE name NOT IN (SELECT name FROM backups ORDER BY name DESC LIMIT 7)", [])
                .map_err(es)?;
            Ok(())
        });
    }
    let dir = files_root(&app)?.join(".prodify-backups");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    write_atomic(&dir.join(format!("{name}.json")), data.as_bytes())?;
    let mut list: Vec<String> = fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".json") && !n.starts_with('.'))
        .collect();
    list.sort();
    while list.len() > 7 {
        let old = list.remove(0);
        let _ = fs::remove_file(dir.join(old));
    }
    Ok(())
}

/// Lists the backups as (name, size in bytes), newest first.
#[tauri::command]
async fn backup_list(app: AppHandle) -> Result<Vec<(String, u64)>, String> {
    if let Some(path) = db_for(&app)? {
        return with_db(&path, |c| {
            let mut st = c.prepare("SELECT name, length(data) FROM backups ORDER BY name DESC").map_err(es)?;
            let rows = st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?.max(0) as u64)))
                .map_err(es)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(es)
        });
    }
    let dir = files_root(&app)?.join(".prodify-backups");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut list: Vec<(String, u64)> = fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            if !n.ends_with(".json") || n.starts_with('.') {
                return None;
            }
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            Some((n.trim_end_matches(".json").to_string(), size))
        })
        .collect();
    list.sort_by(|a, b| b.0.cmp(&a.0));
    Ok(list)
}

/// Reads one backup's JSON.
#[tauri::command]
async fn backup_read(app: AppHandle, name: String) -> Result<String, String> {
    if !backup_name_ok(&name) {
        return Err(format!("Refusing to read backup {name:?}"));
    }
    if let Some(db) = db_for(&app)? {
        return with_db(&db, |c| {
            c.query_row("SELECT data FROM backups WHERE name = ?1", params![name], |r| r.get::<_, String>(0)).map_err(es)
        });
    }
    let path = files_root(&app)?
        .join(".prodify-backups")
        .join(format!("{name}.json"));
    fs::read_to_string(path).map_err(|e| e.to_string())
}

/// Opens the system folder picker (with an optional title). Returns None when the person cancels.
#[cfg(desktop)]
#[tauri::command]
async fn pick_folder(app: AppHandle, title: Option<String>) -> Result<Option<String>, String> {
    let Some(folder) = app
        .dialog()
        .file()
        .set_title(title.as_deref().unwrap_or("Choose where Prodify keeps its files"))
        .blocking_pick_folder()
    else {
        return Ok(None);
    };
    let path = folder.into_path().map_err(|e| e.to_string())?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

/// Phones have no folder picker: Prodify keeps its files in its own storage there.
#[cfg(mobile)]
#[tauri::command]
async fn pick_folder(_app: AppHandle, _title: Option<String>) -> Result<Option<String>, String> {
    Err("Choosing a folder isn't available on phones.".into())
}

/// The app's own files under `dir`: every .md file plus everything in attachments/. Hidden entries are skipped.
fn app_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        let rel = path.strip_prefix(root).map_err(|e| e.to_string())?.to_path_buf();
        if kind.is_dir() {
            app_files(root, &path, out)?;
        } else if kind.is_file()
            && (path.extension().is_some_and(|e| e == "md") || rel.starts_with("attachments"))
        {
            out.push(rel);
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct FolderSwitch {
    dir: String,
    copied: usize,
    skipped: usize,
}

/// Makes `path` the folder Prodify uses. With `copy`, the current files are copied there first;
/// files that already exist in the new folder are never overwritten, and the old folder is left as it is.
#[tauri::command]
async fn set_data_dir(app: AppHandle, path: String, copy: bool) -> Result<FolderSwitch, String> {
    let new = PathBuf::from(path.trim());
    if !new.is_absolute() {
        return Err("Please choose a full folder path.".into());
    }
    let old = files_root(&app)?;
    fs::create_dir_all(&new).map_err(|e| e.to_string())?;
    let (mut copied, mut skipped) = (0, 0);
    if copy && new != old {
        let mut files = Vec::new();
        app_files(&old, &old, &mut files)?;
        for rel in files {
            let dst = new.join(&rel);
            if dst.exists() {
                skipped += 1;
                continue;
            }
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::copy(old.join(&rel), &dst).map_err(|e| format!("Could not copy {}: {e}", rel.display()))?;
            copied += 1;
        }
    }
    let choice = folder_choice_file(&app)?;
    if new == default_root(&app)? {
        let _ = fs::remove_file(&choice);
    } else {
        write_atomic(&choice, new.to_string_lossy().as_bytes())?;
    }
    // let the window show photos from the new folder
    let _ = app.asset_protocol_scope().allow_directory(new.join("attachments"), true);
    Ok(FolderSwitch { dir: new.to_string_lossy().into_owned(), copied, skipped })
}

#[derive(Serialize)]
struct MirrorResult {
    written: usize,
    attachments: usize,
}

/// Copies files into the backup folder (Settings → Storage → Backup folder). It only ever writes there:
/// it never reads the backup's files back and never deletes anything in it. `write` holds Markdown files by key;
/// `attachments` names files in attachments/ to copy, skipping ones the backup already has at the same size.
/// The folder must already exist (so an unplugged drive is reported instead of recreated on the main disk),
/// and it can't be the Prodify folder, inside it, or around it.
#[tauri::command]
async fn mirror_files(
    app: AppHandle,
    dir: String,
    write: BTreeMap<String, String>,
    attachments: Vec<String>,
) -> Result<MirrorResult, String> {
    let dest = PathBuf::from(dir.trim());
    if !dest.is_absolute() {
        return Err("Please choose a full folder path.".into());
    }
    if !dest.is_dir() {
        return Err(format!("The backup folder {} isn't there. Is the drive connected?", dest.display()));
    }
    let root = files_root(&app)?;
    if dest.starts_with(&root) || root.starts_with(&dest) {
        return Err("The backup folder can't be the Prodify folder, a folder inside it, or a folder that contains it.".into());
    }
    let mut written = 0;
    for (key, text) in &write {
        let path = file_path(&dest, key)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        write_atomic(&path, text.as_bytes())?;
        written += 1;
    }
    let db = db_for(&app)?;
    let mut copied = 0;
    for name in &attachments {
        let rel = Path::new(name);
        if name.is_empty() || !rel.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(format!("Refusing to copy {name:?}"));
        }
        let dst = dest.join("attachments").join(rel);
        if let Some(path) = &db {
            let Some(bytes) = db_attachment(path, name)? else { continue };
            if fs::metadata(&dst).map(|m| m.len() == bytes.len() as u64).unwrap_or(false) {
                continue;
            }
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            write_atomic(&dst, &bytes)?;
            copied += 1;
            continue;
        }
        let src = root.join("attachments").join(rel);
        let Ok(meta) = fs::metadata(&src) else { continue };
        if fs::metadata(&dst).map(|m| m.len() == meta.len()).unwrap_or(false) {
            continue;
        }
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::copy(&src, &dst).map_err(|e| format!("Could not copy {name}: {e}"))?;
        copied += 1;
    }
    Ok(MirrorResult { written, attachments: copied })
}

/// Calls the RetroAchievements Web API for the Games collection (Settings → Collections holds the person's own
/// username and API key, which RetroAchievements needs on every call). Only the endpoints Prodify uses are allowed.
#[tauri::command]
async fn ra_api(endpoint: String, params: BTreeMap<String, String>) -> Result<String, String> {
    const ALLOWED: [&str; 5] = [
        "API_GetUserProfile",
        "API_GetUserCompletionProgress",
        "API_GetUserRecentlyPlayedGames",
        "API_GetGameInfoAndUserProgress",
        "API_GetUserAwards",
    ];
    if !ALLOWED.contains(&endpoint.as_str()) {
        return Err(format!("Refusing to call {endpoint:?}"));
    }
    tauri::async_runtime::spawn_blocking(move || {
        let mut req = ureq::get(&format!("https://retroachievements.org/API/{endpoint}.php"))
            .timeout(std::time::Duration::from_secs(30));
        for (k, v) in &params {
            req = req.query(k, v);
        }
        let resp = req.call().map_err(|e| match e {
            ureq::Error::Status(401, _) | ureq::Error::Status(403, _) => "RetroAchievements didn't accept that username and key. The key is the long Web API key from Settings → Keys on retroachievements.org, not your password.".to_string(),
            ureq::Error::Status(code, _) => format!("RetroAchievements answered {code}"),
            other => other.to_string(),
        })?;
        resp.into_string().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[derive(Serialize)]
struct StorageSwitch {
    files: usize,
    attachments: usize,
}

/// Moves the current folder's data between the Markdown folder and app storage.
/// To "db": the folder's files, attachments and backups are copied into the database (replacing what it held
/// before), and the folder is left untouched as a copy. To "md": the app hands over every file as it should be
/// written (`files`, encrypted the folder's way when the account encrypts); Markdown files and attachments
/// already in the folder are from before the switch, so they're moved into .prodify-old/<time>/ rather than
/// deleted, then the files, attachments and backups are written out. The database file is kept.
#[tauri::command]
async fn storage_switch(
    app: AppHandle,
    mode: String,
    files: Option<BTreeMap<String, String>>,
) -> Result<StorageSwitch, String> {
    let root = files_root(&app)?;
    let key = root.to_string_lossy().into_owned();
    let db = db_file(&app, &root)?;
    let mut modes = storage_modes(&app)?;
    if mode == "db" {
        let mut md = BTreeMap::new();
        walk(&root, &root, &mut md)?;
        let mut atts: Vec<(String, Vec<u8>)> = Vec::new();
        let att_dir = root.join("attachments");
        if att_dir.is_dir() {
            for e in fs::read_dir(&att_dir).map_err(|e| e.to_string())?.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if e.file_type().map(|t| t.is_file()).unwrap_or(false) && attachment_name_ok(&n) {
                    atts.push((n, fs::read(e.path()).map_err(|er| er.to_string())?));
                }
            }
        }
        let mut bks: Vec<(String, String)> = Vec::new();
        let bk_dir = root.join(".prodify-backups");
        if bk_dir.is_dir() {
            for e in fs::read_dir(&bk_dir).map_err(|e| e.to_string())?.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if let Some(stem) = n.strip_suffix(".json") {
                    if backup_name_ok(stem) {
                        bks.push((stem.to_string(), fs::read_to_string(e.path()).map_err(|er| er.to_string())?));
                    }
                }
            }
        }
        let counts = StorageSwitch { files: md.len(), attachments: atts.len() };
        with_db(&db, |c| {
            let tx = c.transaction().map_err(es)?;
            tx.execute_batch("DELETE FROM files; DELETE FROM attachments; DELETE FROM backups;").map_err(es)?;
            for (k, v) in &md {
                tx.execute("INSERT INTO files (key, body) VALUES (?1, ?2)", params![k, v]).map_err(es)?;
            }
            for (n, b) in &atts {
                tx.execute("INSERT INTO attachments (name, data) VALUES (?1, ?2)", params![n, b]).map_err(es)?;
            }
            for (n, d) in &bks {
                tx.execute("INSERT INTO backups (name, data) VALUES (?1, ?2)", params![n, d]).map_err(es)?;
            }
            tx.commit().map_err(es)
        })?;
        modes.insert(key, "db".into());
        storage_save(&app, &modes)?;
        return Ok(counts);
    }
    let files = files.ok_or("The files to write are missing")?;
    let (atts, bks) = with_db(&db, |c| {
        let mut st = c.prepare("SELECT name, data FROM attachments").map_err(es)?;
        let atts = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))
            .map_err(es)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(es)?;
        let mut st = c.prepare("SELECT name, data FROM backups").map_err(es)?;
        let bks = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(es)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(es)?;
        Ok((atts, bks))
    })?;
    let mut old = Vec::new();
    app_files(&root, &root, &mut old)?;
    if !old.is_empty() {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let aside = root.join(".prodify-old").join(stamp.to_string());
        for rel in &old {
            let dst = aside.join(rel);
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::rename(root.join(rel), &dst).map_err(|e| format!("Could not move {} aside: {e}", rel.display()))?;
        }
    }
    for (k, v) in &files {
        let path = file_path(&root, k)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        write_atomic(&path, v.as_bytes())?;
    }
    if !atts.is_empty() {
        let dir = root.join("attachments");
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        for (n, b) in &atts {
            if attachment_name_ok(n) {
                write_atomic(&dir.join(n), b)?;
            }
        }
    }
    if !bks.is_empty() {
        let dir = root.join(".prodify-backups");
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        for (n, d) in &bks {
            if backup_name_ok(n) {
                write_atomic(&dir.join(format!("{n}.json")), d.as_bytes())?;
            }
        }
    }
    modes.remove(&key);
    storage_save(&app, &modes)?;
    *DB.lock().map_err(|e| e.to_string())? = None;
    Ok(StorageSwitch { files: files.len(), attachments: atts.len() })
}

#[tauri::command]
async fn notify(app: AppHandle, title: String, body: String) -> Result<(), String> {
    app.notification()
        .builder()
        .title(title)
        .body(body)
        .show()
        .map_err(|e| e.to_string())
}

/// Opens a web page (a catalogue link from Collections) in the default browser. Only http(s) links are allowed.
#[tauri::command]
async fn open_link(app: AppHandle, url: String) -> Result<(), String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("Only web links can be opened".into());
    }
    app.opener().open_url(url, None::<&str>).map_err(|e| e.to_string())
}

#[tauri::command]
async fn open_folder(app: AppHandle) -> Result<(), String> {
    let root = files_root(&app)?;
    app.opener()
        .open_path(root.to_string_lossy(), None::<&str>)
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // photos in a custom folder are outside the default scope in tauri.conf.json
            // decrypted copies opened last time are removed
            if let Ok(dir) = open_temp_dir(app.handle()) {
                let _ = fs::remove_dir_all(dir);
            }
            if let Ok(root) = files_root(app.handle()) {
                let _ = app.asset_protocol_scope().allow_directory(root.join("attachments"), true);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            load_all,
            sync_files,
            kv_set,
            save_download,
            export_attachment,
            save_attachment,
            download_attachment,
            pick_folder,
            set_data_dir,
            mirror_files,
            storage_switch,
            ra_api,
            read_attachment,
            list_attachments,
            open_temp_file,
            notify,
            open_folder,
            open_link,
            open_attachment,
            link_info,
            ai_complete,
            backup_write,
            backup_list,
            backup_read
        ])
        .run(tauri::generate_context!())
        .expect("error while running Prodify");
}
