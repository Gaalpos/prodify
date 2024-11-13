const {model, Schema} = require ("mongoose")
const CheckItem = require("./CheckItem")

const ListSchema = new Schema({
    name:{
        type: String,
        required: true,
    },
    items : [CheckItem],
})

module.exports = model("List", ListSchema)