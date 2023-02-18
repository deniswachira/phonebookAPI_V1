const router = require('express').Router();
const Contact = require('../models/Contact');

//get all contacts
router.get('/', async (req, res) => {
    try {
        const contacts = await Contact.find();
        if (contacts) {
            res.status(200).json(contacts)
        } else {
            res.status(200).json("No Contacts Found!")
        }
    } catch (err) {
        res.status(500).json(err);
    }
});

router.post('/contacts', async (req, res) => {
    const newContact = new Contact(req.body);
    try {
        const savedContact = await newContact.save();
        res.status(200).json(savedContact);
    } catch (err) {
        res.status(500).json(err);
    }
});

router.delete('/contacts/:id', (req, res) => {
    const id = req.params.id;
    Contact.deleteOne({ _id: id }, (err) => {
        if (err) {
            res.status(500).json({ error: 'Could not delete contact' });
        } else {
            res.status(200).json({ message: 'Contact deleted successfully' });
        }
    });
});

module.exports = router;