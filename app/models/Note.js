const { model, Schema } = require("mongoose");

const Note = new Schema({
  name: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
});

module.exports = model("Note", Note);
