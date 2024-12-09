const { BrowserWindow, ipcMain } = require("electron");
const Note = require("./models/Note");
const Task = require("./models/Task");
const Project = require("./models/Project");
const ProjectNote = require("./models/ProjectNote");
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
    autoHideMenuBar: false,
    fullscreen: false,
  });
  win.loadFile("app/index.html");
  win.maximize();
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


ipcMain.on("new-task", async (e, arg) => {
  const newTask = new Task(arg);
  const taskSaved = await newTask.save();
  e.reply("new-task-created", JSON.stringify(taskSaved));
});

ipcMain.on("get-tasks", async (e, args) => {
  const tasks = await Task.find();
  e.reply("get-tasks", JSON.stringify(tasks));
});

ipcMain.on("delete-task", async (e, args) => {
  const taskDeleted = await Task.findByIdAndDelete(args);
  e.reply("delete-task-success", JSON.stringify(taskDeleted));
});


ipcMain.on("update-task", async (e, args) => {
  console.log(args);
  const updatedTask = await Task.findByIdAndUpdate(
    args.idTaskToUpdate,
    { name: args.name },
    { new: true }
  );
  e.reply("update-task-success", JSON.stringify(updatedTask))
});

ipcMain.on("complete-task", async (e, id) => {
  try {
    const updatedTask = await Task.findByIdAndUpdate(
      id,
      { completed: true },
      { new: true }
    );
    e.reply("complete-task-success", JSON.stringify(updatedTask));
  } catch (err) {
    console.error("Error marking task as complete:", err);
  }
});

ipcMain.on("new-project", async (e, arg) => {
  const newProject = new Project(arg);
  const projectSaved = await newProject.save();
  e.reply("new-project-created", JSON.stringify(projectSaved));
});

ipcMain.on("get-projects", async (e, arg) => {
  const projects = await Project.find();
  e.reply("get-projects", JSON.stringify(projects));
});

ipcMain.on("delete-project", async (e, args) => {
  const projectDeleted = await Project.findByIdAndDelete(args);
  e.reply("delete-project-success", JSON.stringify(projectDeleted));
})

ipcMain.on("new-project-note", async (e, arg) => {
  const newProjectNote = new ProjectNote(arg);
  const projectNoteSaved = await newProjectNote.save();
  e.reply("new-project-note-created", JSON.stringify(projectNoteSaved));
});

ipcMain.on("get-project-notes", async (e, arg) => {
  const projectNotes = await ProjectNote.find();
  e.reply("get-project-notes", JSON.stringify(projectNotes));
});

ipcMain.on("new-project-task", async (e, arg) => {
  const newProjectNote = new ProjectNote(arg);
  const projectNoteSaved = await newProjectNote.save();
  e.reply("new-project-task-created", JSON.stringify(projectNoteSaved));
});

ipcMain.on("get-project-tasks", async (e, arg) => {
  const projectTasks = await ProjectNote.find();
  e.reply("get-project-tasks", JSON.stringify(projectTasks));
});

module.exports = { createWindow };
