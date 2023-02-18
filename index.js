const express = require('express');
const app = express();
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const contacts = require('./routes/contact');
const cors = require('cors');

//middlewares
app.use(express.json());
dotenv.config();
app.use(cors());

mongoose.set('strictQuery', false);
mongoose.connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(console.log("connected to mongodb"))
    .catch((err) => console.log(err));


//define my routes
app.use("/api", contacts);

app.listen(process.env.PORT || 6000, () => {
    console.log('Server running on port 6000');
});