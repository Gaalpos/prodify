const { model, Schema } = require("mongoose");
const mongoose = require("mongoose");

const ProjectNote = new Schema({
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
        required: true,
        ref: "Project"
    }
});

module.exports = model("ProjectNote", ProjectNote);
