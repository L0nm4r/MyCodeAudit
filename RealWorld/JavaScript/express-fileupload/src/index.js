const express = require('express');
const fileUpload = require('express-fileupload');
const app = express();

app.use(fileUpload({ parseNested: true }));

app.get('/', (req, res) => {
    res.end('express-fileupload poc');
});

app.listen(7777)