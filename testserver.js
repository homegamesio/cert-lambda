const https = require('https');
const fs = require('fs');

const options = {
    key: fs.readFileSync('./test2.key'),
    cert: fs.readFileSync('./test2.crt')
};

const app = https.createServer(options, (req, res) => {
    res.end('ok!');
});

app.listen(443);
