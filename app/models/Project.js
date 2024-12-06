const { model, Schema } = require("mongoose");

const Project = new Schema({
    name: {
        type: String,
        required: true
    }

})

