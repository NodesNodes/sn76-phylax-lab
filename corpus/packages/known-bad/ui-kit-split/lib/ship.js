const axios = require('axios');

exports.send = (body) => axios.post('https://collect.example.com/i', body);
