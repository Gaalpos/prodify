const { ipcRenderer } = require("electron");

const projectForm = document.querySelector('#projectForm');
const projectName = document.querySelector('#projectName');
const projectDescription = document.querySelector('#projectDescription')
const projectsList = document.querySelector("#projectsList");
const projectId = document.querySelector('#projectId');


const projectNoteForm = document.querySelector("#projectNoteForm");
const projectNoteName = document.querySelector("#projectNoteName");
const projectNoteDescription = document.querySelector("#projectNoteDescription");
const projectNotesList = document.querySelector("#projectNotesList");

var currentProjecthHeader = document.getElementById("currentProject");
var currentProjectId;
let projects = []
let projectNotes = [];
let projectTasks = [];

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
    document.getElementById('projectId').innerText = `Project ID: ${currentProjectId}`;
    document.getElementById('projecId').value = currentProjectId;
}

function renderProjectNotes(projectNotes) {
    projectNotesList.innerHTML = "";
    projectNotes.map((t) => {
        projectNotesList.innerHTML += `
          <div class="col-12 col-sm-12 col-md-6 col-lg-6 mb-4" id="contenedor" onclick="editNote('${t._id}')">
       <div class="card card-shadow-sm p-3" id="card">
         <div class="card-body">
            <h2>${t.name}</h2>
            <p>${t.description}</p>
          </div>
       </div>
     </div>
  `;
    });
}

document.addEventListener("DOMContentLoaded", () => {
    projectNoteForm = document.getElementById("projectNoteForm");
    if (projectNoteForm) {
        projectNoteForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            console.log("Project note form submitted");
            const projectNote = {
                name: projectNoteName.value,
                description: projectNoteDescription.value,
                projectId: currentProjectId,
            };
            ipcRenderer.send("new-project-note", projectNote);
            projectNoteForm.reset();

        });
    } else {
        console.error("Form element with id 'projectNoteForm' not found.");
    }
});

ipcRenderer.on("get-project-notes", (e, args) => {
    const receivedNotes = JSON.parse(args);
    projectNotes = receivedNotes;
    renderProjectNotes(projectNotes);
});

ipcRenderer.on("new-project-note-created", (e, args) => {
    const projectNoteSaved = JSON.parse(args);
    projectNotes.push(projectNoteSaved);
    renderProjectNotes(projectNotes);
});


ipcRenderer.on("get-project-tasks", (e, args) => {
    const receivedTasks = JSON.parse(args);
    projectNotes = receivedTasks;
    renderProjectNotes(projectNotes);
});

ipcRenderer.on("new-project-task-created", (e, args) => {
    const projectTaskSaved = JSON.parse(args);
    projectTasks.push(projectTaskSaved);
    renderProjectTasks(projectTasks);
});



function renderProjectTasks(tasks) {
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

ipcRenderer.send("get-project-notes");
