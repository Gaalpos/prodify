const { ipcRenderer } = require("electron");

const tasksList = document.querySelector("#tasksList");
const taskForm = document.querySelector("#taskForm");
const taskName = document.querySelector("#taskName");

let updateStatus = false;
let tasks = [];

function deleteTask(id) {
    event.stopPropagation();
     const response = confirm("Delete task?");
     if (response) {
       ipcRenderer.send("delete-task", id);
       taskName.value = '';
       console.log("deleted")
     }
     return;
} 
   

function renderTasks(tasks) {
    tasksList.innerHTML = "";
    tasks.map((t) => {
      tasksList.innerHTML += `
        <div class="task-container" id="contenedor" onclick="editTask('${t._id}')">
           <div class="card" id="card">
               <div class="card-body">
                   <div class="task-header">
                       <button class="btn checkButton" onclick="completeTask('${t._id}')"><svg  xmlns="http://www.w3.org/2000/svg"  
                       width="24"  height="24"  viewBox="0 0 24 24"  fill="none"  stroke="currentColor"  stroke-width="2"  
                       stroke-linecap="round"  stroke-linejoin="round"  class="icon icon-tabler icons-tabler-outline 
                       icon-tabler-check"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M5 12l5 5l10 -10" /></svg></button>
                       <h2 id="text-to-copy-title">${t.name}</h2>
                       <button class="btn deleteButton" onClick="deleteTask('${t._id}')">Delete</button>
                   </div>
               </div>
           </div>
        </div>
      `;
    });
  }

taskForm.addEventListener("submit", async (e) =>{
    e.preventDefault();
    const task = {
         name: taskName.value,
     };
    ipcRenderer.send("new-task", task);
    taskForm.reset();
})

ipcRenderer.on("new-task-created", (e, arg) => {
    console.log(arg);
    const taskSaved = JSON.parse(arg);
    tasks.push(taskSaved);
    console.log(tasks);
    renderTasks(tasks);
});


ipcRenderer.send("get-tasks");

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

ipcRenderer.on("update-task-succes", (e,args) =>{
    const updatedTask = JSON.parse(args);
     tasks = tasks.map((t,i) => {
        if(t._id === updatedTask._id){
            t.name = updatedTask.name;
        }
        return t;
    })
    renderTasks(tasks)
});