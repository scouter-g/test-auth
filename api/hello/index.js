module.exports = async function (context, req) {
    context.res = {
        status: 200,
        body: {
            received: req.body || null
        }
    };
};
