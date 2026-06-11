const NodeCache = require("node-cache");

const cache = new NodeCache({
    stdTTL: 60, //limit 1 min
    checkperiod: 60 //check expire 
});

module.exports = cache;