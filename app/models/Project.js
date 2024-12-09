const { model, Schema } = require("mongoose");

const Project = new Schema({
    name: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: false
    }
})

module.exports = model("Project", Project)