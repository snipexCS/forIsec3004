// attacker-server.js
// Tiny static server hosting attacker-page.html on a DIFFERENT port
// (simulating a different origin: http://localhost:6000) so the demo
// reflects a real cross-site scenario rather than a same-origin request.
const express = require('express');
const path = require('path');
const app = express();
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'attacker-page.html')));
app.listen(5050, () => console.log('Attacker page hosted at http://localhost:5050'));
