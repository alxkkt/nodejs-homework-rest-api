const mongoose = require("mongoose");

const contactSchema = mongoose.Schema({
  name: String.require,
  email: String.require,
  phone: String.require,
});

const contacts = mongoose.model("contact", contactSchema);
