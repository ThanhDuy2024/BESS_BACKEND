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

module.exports = funcPagination;