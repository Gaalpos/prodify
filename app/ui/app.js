const { ipcRenderer } = require("electron");

const taskForm = document.querySelector("#taskForm");
const taskName = document.querySelector("#taskName");
const taskDescription = document.querySelector("#taskDescription");
const taskList = document.querySelector("#taskList");

let updateStatus = false;
let idTaskToUpdate = "";

function deleteTask(id) {
  event.stopPropagation();
  const response = confirm("Are you sure you want to delete it?");
  if (response) {
    ipcRenderer.send("delete-task", id);
    // Ensure the form is reset and inputs are enabled
    taskName.value = '';
    taskDescription.value = '';
    updateStatus = false;
    document.getElementById('saveButton').innerHTML = "Save";
    console.log("deleted")
  }
  return;
}

function editTask(id) {
  document.getElementById('saveButton').innerHTML = "Edit note";
  updateStatus = true;
  idTaskToUpdate = id;
  const task = tasks.find((task) => task._id === id);
  taskName.value = task.name;
  taskDescription.value = task.description;
  
}
 function renderTasks(tasks) {
  taskList.innerHTML = "";  // Clear the existing list
  tasks.map((t) => {
    taskList.innerHTML += `
      <div class="col-12 col-sm-12 col-md-6 col-lg-6 mb-4" id="contenedor" onclick="editTask('${t._id}')">
    <div class="card card-shadow-sm p-3" id="card">
          <div class="card-body">
          <h2 id="text-to-copy-title">${t.name}</h2>
           <p id="text-to-copy-body">${t.description}</p>
       <button class="btn copyButton" onclick="copyText()">Copy</button>
           <button class="btn deleteButton"onclick="deleteTask('${t._id}')">Delete</button>
       </div>
      </div>
      </div>
`;
 });
 }

let tasks = [];

ipcRenderer.send("get-tasks");

taskForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  document.getElementById('saveButton').innerHTML = "Save";
  const task = {
    name: taskName.value,
    description: taskDescription.value,
  };

  if (!updateStatus) {
    ipcRenderer.send("new-task", task);
  } else {
    ipcRenderer.send("update-task", { ...task, idTaskToUpdate });
  }

  taskForm.reset();
});

ipcRenderer.on("new-task-created", (e, arg) => {
  console.log(arg);
  const taskSaved = JSON.parse(arg);
  tasks.push(taskSaved);
  console.log(tasks);
  renderTasks(tasks);
 // alert("Task Created Successfully");
  taskName.focus();
});

ipcRenderer.on("get-tasks", (e, args) => {
  const receivedTasks = JSON.parse(args);
  tasks = receivedTasks;
  renderTasks(tasks);
});

ipcRenderer.on("delete-task-success", (e, args) => {
  const deletedTask = JSON.parse(args);
  const newTasks = tasks.filter((t) => {
    return t._id !== deletedTask._id;
  });
  tasks = newTasks;
  renderTasks(tasks);
});

ipcRenderer.on("update-task-success", (e, args) => {

  updateStatus = false;
  const updatedTask = JSON.parse(args);
  tasks = tasks.map((t, i) => {
    if (t._id === updatedTask._id) {
      t.name = updatedTask.name;
      t.description = updatedTask.description;
    }
    return t;
  });
  renderTasks(tasks);
});


function copyText() {
 event.stopPropagation();
  // Get the text from the div
  const body = document.getElementById('text-to-copy-body').innerText;
  const title = document.getElementById('text-to-copy-title').innerText;
  const note = `${title}\n\n${body}`;

  // Use the Clipboard API to write the text to the clipboard
  navigator.clipboard.writeText(note).then(function() {
     // alert('Text copied to clipboard!');
  }).catch(function(err) {
      console.error('Error copying text: ', err);
  });
}