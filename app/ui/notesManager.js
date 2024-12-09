const { ipcRenderer } = require("electron");

const noteForm = document.querySelector("#noteForm");
const noteName = document.querySelector("#noteName");
const noteDescription = document.querySelector("#noteDescription");
const noteList = document.querySelector("#notesList");

let updateStatus = false;
let idNoteToUpdate = "";
let notes = [];

function deleteNote(id) {
  event.stopPropagation();
  const response = confirm("Delete note?");
  if (response) {
    ipcRenderer.send("delete-note", id);
    noteName.value = '';
    noteDescription.value = '';
    updateStatus = false;
    document.getElementById('saveButton').innerHTML = "Save";
  }
  return;
}
function copyText(id) {
  event.stopPropagation();
  const note = notes.find((note) => note._id === id);
  copiedName = note.name;
  copiedDescription = note.description;
  const copiedNote = `"${copiedName}"\n\n${copiedDescription}`;

  navigator.clipboard.writeText(copiedNote).then(function () {
  }).catch(function (err) {
    console.error('Error copying text: ', err);
  });
}

function editNote(id) {
  document.getElementById('saveButton').innerHTML = "Edit note";
  updateStatus = true;
  idNoteToUpdate = id;
  const note = notes.find((note) => note._id === id);
  noteName.value = note.name;
  noteDescription.value = note.description;
}


function renderNotes(notes) {
  noteList.innerHTML = "";
  notes.map((t) => {
    noteList.innerHTML += `
     <div class="col-12 col-sm-12 col-md-6 col-lg-6 mb-4" id="contenedor" onclick="editNote('${t._id}')">
       <div class="card card-shadow-sm p-3" id="card">
         <div class="card-body">
            <h2>${t.name}</h2>
            <p>${t.description}</p>
            <button class="btn copyButton" onclick="copyText('${t._id}')">Copy</button>
            <button class="btn deleteButton" onclick="deleteNote('${t._id}')">Delete</button>
          </div>
       </div>
     </div>
`;
  });
}


// IPC
ipcRenderer.on("get-notes", (e, args) => {
  const receivedNotes = JSON.parse(args);
  notes = receivedNotes;
  renderNotes(notes);
});

ipcRenderer.on("new-note-created", (e, args) => {
  const noteSaved = JSON.parse(args);
  notes.push(noteSaved);
  renderNotes(notes);
});


ipcRenderer.on("delete-note-success", (e, args) => {
  const deletedNote = JSON.parse(args);
  const newNotes = notes.filter((t) => {
    return t._id !== deletedNote._id;
  });
  notes = newNotes;
  renderNotes(notes);

});

ipcRenderer.on("update-note-success", (e, args) => {
  updateStatus = false;
  const updatedNote = JSON.parse(args);
  notes = notes.map((t, i) => {
    if (t._id === updatedNote._id) {
      t.name = updatedNote.name;
      t.description = updatedNote.description;
    }
    return t;
  });
  renderNotes(notes);
});


noteForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  document.getElementById('saveButton').innerHTML = "Save";
  const note = {
    name: noteName.value,
    description: noteDescription.value,
  };

  if (!updateStatus) {
    ipcRenderer.send("new-note", note);
  } else {
    ipcRenderer.send("update-note", { ...note, idNoteToUpdate });
  }
  noteForm.reset();
});


ipcRenderer.send("get-notes");