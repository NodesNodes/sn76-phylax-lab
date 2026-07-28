const axios = require('axios');
const config = require('./config');

exports.send = (path, body) =>
  axios.post(config.baseUrl + path, body, {headers: {Authorization: 'Bearer ' + config.apiKey}});
