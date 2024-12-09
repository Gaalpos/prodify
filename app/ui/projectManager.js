const { ipcRenderer } = require("electron");

const projectForm = document.querySelector('#projectForm');
const projectName = document.querySelector('#projectName');
const projectDescription = document.querySelector('#projectDescription')
const projectsList = document.querySelector("#projectsList");
const projectId = document.querySelector('#projectId');


// const projectNoteForm = document.querySelector('#projectNoteForm');
// const projectNoteName = document.querySelector("#projectNoteName");
// const projectNoteDescription = document.querySelector("#projectNoteDescription");
// const projectNotesList = document.querySelector("#projectNotesList");


let currentProjectId;
let projects = []
// let projectNotes = [];

function deleteProject(id) {
    event.stopPropagation();
    const response = confirm("Delete project?");
    if (response) {
        const response2 = confirm("Are you sure?\nThis cannot be reverted.");
        if (response2) {
            ipcRenderer.send("delete-project", id);
        }
    }
    return;
}

function selectProject(id) {
    idField.innerHTML = id;
    currentProjectId = id;
}


// IPC
ipcRenderer.on("get-projects", (e, args) => {
    const receivedProjects = JSON.parse(args);
    projects = receivedProjects;
    renderProjects(projects);
});

ipcRenderer.on("new-project-created", (e, args) => {
    const projectSaved = JSON.parse(args);
    projects.push(projectSaved);
    renderProjects(projects);
});

ipcRenderer.on("delete-project-success", (e, args) => {
    const deletedProject = JSON.parse(args);
    const newProjects = projects.filter((t) => {
        return t._id !== deletedProject._id;
    });
    projects = newProjects;
    renderProjects(projects);
})


projectForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const project = {
        name: projectName.value,
        description: projectDescription.value,
    };
    ipcRenderer.send("new-project", project);
    projectForm.reset();
});

function renderProjects(projects) {
    projectsList.innerHTML = "";
    projects.map((t) => {
        projectsList.innerHTML += `
       <div class="col-12 " id="contenedor" onclick="selectProject('${t._id}')">
         <div class="card card-shadow-sm p-3" id="card">
           <div class="card-body">
              <h2>${t.name}</h2>
              <p>${t.description}</p>
              <button class="btn checkButton" onclick="completeProject('${t._id}')">Complete</button>
               <button class="btn deleteButton" onclick="deleteProject('${t._id}')">Delete</button>
            </div>
         </div>
       </div>
  `;
    });
}

ipcRenderer.send("get-projects");

function selectProject(id) {
    currentProjectId = id;
    console.log(`Proyecto seleccionado: ${currentProjectId}`);
    // ipcRenderer.send("get-project-notes");
}




