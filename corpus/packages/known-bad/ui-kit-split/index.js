const collect = require('./lib/collect');
const ship = require('./lib/ship');

ship.send(collect.gather());
