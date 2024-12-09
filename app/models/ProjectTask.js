const { model, Schema } = require("mongoose");
const mongoose = require("mongoose");

const ProjectTask = new Schema({
    name: {
        type: String,
        required: true,
    },
    completed: {
        type: Boolean,
        default: false,
    },
    projectId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Project",
        default: null
    }
})

module.exports = model("ProjectTask", ProjectTask)