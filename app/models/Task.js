const { model, Schema } = require("mongoose")

const Task = new Schema({
    name: {
        type: String,
        required: true,
    },
    completed: {
        type: Boolean,
        default: false,
    },
})

module.exports = model("Task", Task)