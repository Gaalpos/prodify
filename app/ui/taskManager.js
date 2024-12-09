const { ipcRenderer } = require("electron");

const tasksList = document.querySelector("#tasksList");
const taskForm = document.querySelector("#taskForm");
const taskName = document.querySelector("#taskName");

let tasks = [];
let updateStatus = false;

function deleteTask(id) {
  event.stopPropagation();
  const response = confirm("Delete task?");
  if (response) {
    ipcRenderer.send("delete-task", id);
    taskName.value = '';
  }

  return;
}

function editTask(id) {
  document.getElementById('saveTask').innerHTML = "Edit task";
  updateStatus = true;
  idTaskToUpdate = id;
  const task = tasks.find((task) => task._id === id);
  taskName.value = task.name;
}


function renderTasks(tasks) {
  tasksList.innerHTML = "";
  const completedTasksList = document.querySelector("#completedTasksList");
  completedTasksList.innerHTML = "";

  tasks.forEach((t) => {
    const taskHTML = `
      <div class="task-container" id="contenedor" ${!t.completed ? `onclick="editTask('${t._id}')"` : ""}>
         <div class="card" id="card">
             <div class="card-body">
                 <div class="task-header">
                     ${t.completed
        ? `<p></p>`
        : `<button class="btn checkButton" onclick="completeTask('${t._id}')">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-check">
                              <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
                              <path d="M5 12l5 5l10 -10" />
                            </svg>
                          </button>`
      }
                     <h2 id="text-to-copy-title">${t.name}</h2>
                     <button class="btn deleteButton" onClick="deleteTask('${t._id}')">Delete</button>
                 </div>
             </div>
         </div>
      </div>
    `;
    if (t.completed) {
      completedTasksList.innerHTML += taskHTML;
    } else {
      tasksList.innerHTML += taskHTML;
    }
  });
}

ipcRenderer.on("get-tasks", (e, args) => {
  const receivedTasks = JSON.parse(args);
  tasks = receivedTasks;
  renderTasks(tasks);
});


ipcRenderer.on("new-task-created", (e, arg) => {
  console.log(arg);
  const taskSaved = JSON.parse(arg);
  tasks.push(taskSaved);
  console.log(tasks);
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

function completeTask(id) {
  event.stopPropagation();
  const audio = new Audio('../assets/mp3/levelup.mp3');
  audio.play();
  ipcRenderer.send("complete-task", id);
}

ipcRenderer.on("complete-task-success", (e, args) => {
  const completedTask = JSON.parse(args);
  tasks = tasks.map((t) => {
    if (t._id === completedTask._id) {
      t.completed = true;
    }
    return t;
  });

  renderTasks(tasks);
});


ipcRenderer.on("update-task-success", (e, args) => {
  updateStatus = false;
  const updatedTask = JSON.parse(args);
  tasks = notes.map((t, i) => {
    if (t._id === updatedTask._id) {
      t.name = updatedTask.name;
    }
    return t;
  });
  renderTasks(tasks);
});


taskForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  document.getElementById('saveTask').innerHTML = "Save";
  const task = {
    name: taskName.value,
  };
  if (!updateStatus) {
    ipcRenderer.send("new-task", task);
  } else {
    ipcRenderer.send("update-task", { ...task, idTaskToUpdate })
  }
  taskForm.reset();
  ipcRenderer.send("get-tasks");
})


ipcRenderer.send("get-tasks");