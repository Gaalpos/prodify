const { model, Schema } = require("mongoose");
const mongoose = require("mongoose");

const Note = new Schema({
  name: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },

  projectId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Project",
    default: null
  }
});

module.exports = model("Note", Note);
