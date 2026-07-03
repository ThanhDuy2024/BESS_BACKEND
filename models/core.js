const NodeCache = require("node-cache");

const cache = new NodeCache({
    stdTTL: 60, //limit 1 min
    checkperiod: 60 //check expire 
});

const capitalizeFirstLetter = (string) => {
  return string.charAt(0).toUpperCase() + string.slice(1);
}

const funcPagination = (page, limit, totalRecord) => {
    const totalPage = Math.ceil(totalRecord / limit);
    
    let offset = 0
    if(Number(page) > 0 && Number(page) <= totalPage) {
        offset = (Number(page) - 1) * limit;
    };

    return {
        offset: offset,
        totalPage: totalPage
    }
};
module.exports = {
    cache,
    capitalizeFirstLetter,
    funcPagination,
};