const {model, Schema} = require ("mongoose")

const CheckItem = new Schema ({
    name: {
        type: String,
        required: true,
    },
    completed: {
        type: Boolean,
        required: true,
        default: false,
    }
})

module.exports = model("CheckItem", CheckItem)