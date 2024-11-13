const { ipcRenderer } = require("electron");

const noteForm = document.querySelector("#noteForm");
const noteName = document.querySelector("#noteName");
const noteDescription = document.querySelector("#noteDescription");
const noteList = document.querySelector("#notesList");

let updateStatus = false;
let idNoteToUpdate = "";

function deleteNote(id) {
 event.stopPropagation();
  const response = confirm("Are you sure you want to delete it?");
  if (response) {
    ipcRenderer.send("delete-note", id);
    // Ensure the form is reset and inputs are enabled
    noteName.value = '';
    noteDescription.value = '';
    updateStatus = false;
    document.getElementById('saveButton').innerHTML = "Save";
    console.log("deleted")
  }
  return;
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
          <h2 id="text-to-copy-title">${t.name}</h2>
           <p id="text-to-copy-body">${t.description}</p>
       <button class="btn copyButton" onclick="copyText()">Copy</button>
           <button class="btn deleteButton"onclick="deleteNote('${t._id}')">Delete</button>
       </div>
      </div>
      </div>
`;
 });
 }

let notes = [];

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

ipcRenderer.on("new-note-created", (e, arg) => {
  console.log(arg);
  const noteSaved = JSON.parse(arg);
  notes.push(noteSaved);
  console.log(notes);
  renderNotes(notes);
});

ipcRenderer.send("get-notes");

ipcRenderer.on("get-notes", (e, args) => {
  const receivedNotes = JSON.parse(args);
  notes = receivedNotes;
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


function copyText() {
  event.stopPropagation();
  const body = document.getElementById('text-to-copy-body').innerText;
  const title = document.getElementById('text-to-copy-title').innerText;
  const note = `${title}\n\n${body}`;

  navigator.clipboard.writeText(note).then(function() {
  }).catch(function(err) {
      console.error('Error copying text: ', err);
  });
}