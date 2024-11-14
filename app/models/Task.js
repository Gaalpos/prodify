const {model, Schema} = require ("mongoose")

const Task = new Schema ({
    name: {
        type: String,
        required: true,
    }
})

module.exports = model("Task", Task)