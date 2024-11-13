const { model, Schema } = require("mongoose");

// Definimos el esquema para los elementos de la lista
const listItemSchema = new Schema({
  name: {
    type: String,
    required: true,
  },
  completed: {
    type: Boolean,
    default: false,
  },
});

// Definimos el esquema para la lista de tareas
const listSchema = new Schema({
  title: {
    type: String,
    required: true,
  },
  items: [listItemSchema], // Array de elementos de la lista
});

module.exports = model("List", listSchema);
