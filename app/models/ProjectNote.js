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
        type: String,
        required: true
    }

});

module.exports = model("ProjectNote", ProjectNote);
