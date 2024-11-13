const { BrowserWindow, ipcMain } = require("electron");
const Note = require("./models/Note");
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({
    width: 1080,
    height: 720,
    icon: path.join(__dirname, './assets', 'logo.png'),
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    autoHideMenuBar: true,
    fullscreen: false,
  });

  win.loadFile("app/index.html");
  //win.maximize();
}

ipcMain.on("new-note", async (e, arg) => {
  const newNote = new Note(arg);
  const noteSaved = await newNote.save();
  e.reply("new-note-created", JSON.stringify(noteSaved));
});

ipcMain.on("get-notes", async (e, arg) => {
  const notes = await Note.find();
  e.reply("get-notes", JSON.stringify(notes));
});

ipcMain.on("delete-note", async (e, args) => {
  const noteDeleted = await Note.findByIdAndDelete(args);
  e.reply("delete-note-success", JSON.stringify(noteDeleted));
});

ipcMain.on("update-note", async (e, args) => {
  console.log(args);
  const updatedNote = await Note.findByIdAndUpdate(
    args.idNoteToUpdate,
    { name: args.name, description: args.description },
    { new: true }
  );
  e.reply("update-note-success", JSON.stringify(updatedNote));
});

module.exports = { createWindow };
