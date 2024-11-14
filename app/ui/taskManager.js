const { ipcRenderer } = require("electron");

const tasksList = document.querySelector("#tasksList");
const taskForm = document.querySelector("#taskForm");
const taskName = document.querySelector("#taskName");

let updateStatus = false;
let tasks = [];

// function deleteTask(id) {
//      const response = confirm("Delete note?");
//      if (response) {
//        ipcRenderer.send("delete-note", id);
//        // Ensure the form is reset and inputs are enabled
//        noteName.value = '';
//        noteDescription.value = '';
//        updateStatus = false;
//        document.getElementById('saveButton').innerHTML = "Save";
//        console.log("deleted")
//      }
//      return;
// } 


function renderTasks(tasks){
tasksList.innerHTML = "";
tasks.map((t) => {
    tasksList.innerHTML += `
      <div class="col-12 col-sm-12 col-md-6 col-lg-6 mb-4" id="contenedor" onclick="completeTask('${t._id}')">
         <div class="card card-shadow-sm p-3" id="card">
             <div class="card-body">
                 <h2 id="text-to-copy-title">${t.name}</h2>
             </div>
         </div>
      </div>
`;
})  ;   
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

ipcRenderer.on("delete-task-success", (e, args) =>{

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