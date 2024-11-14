const { BrowserWindow, ipcMain } = require("electron");
const Note = require("./models/Note");
const Task = require("./models/Task");
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


/*          NOTES       */
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

/*     TASKS       */
ipcMain.on("new-task", async (e, arg) => {
  const newTask = new Task(arg);
  const taskSaved = await newTask.save();
  e.reply("new-task-created", JSON.stringify(taskSaved));
});

ipcMain.on("get-tasks", async (e, arg) => {
  const tasks = await Task.find();
  e.reply("get-tasks", JSON.stringify(tasks));
});

ipcMain.on("delete-task", async (e, args) => {
  const taskDeleted = await Task.findByIdAndDelete(args);
  e.reply("delete-task-success", JSON.stringify(taskDeleted));
});

ipcMain.on("update-task", async (e,args) =>{
  console.log(args);
  const updatedTask = await Task.findByIdAndUpdate(
    args.idTaskToDelete,
    {name : args.name},
    {new:true}
  )
})

module.exports = { createWindow };
