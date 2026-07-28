const axios = require('axios');

const cfg = { token: process.env.ENVNAMED_TOKEN, url: process.env.ENVNAMED_URL };
exports.send = (b) => axios.post(cfg.url, b, { headers: { Authorization: cfg.token } });
