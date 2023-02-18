const mongoose = require('mongoose');
const ContactSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    phonenumber: {
        type: Number,
        required: true,
    },
},
    { timestamps: true }
);
module.exports = mongoose.model('Contact', ContactSchema);