const jwt = require("jsonwebtoken");
const apiData = require("../routes/dataProcess");
const { errorMonitor } = require("node-cache");
const verify = async (req, res, next) => {
    try {
        const token = req.headers.token;

        //Check token
        if (!token) {
            return res.status(401).json({
                status: false,
                msg: "Missing token"
            })
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        //check expire and secret key
        if (!decoded) {
            return res.status(400).json({
                status: false,
                msg: "Invalid or expired token"
            })
        }

        //check user info
        const user = await apiData.funcTable("func_getuser", `(${decoded.id})`);

        if (!user.status) {
            return res.status(500).json({
                status: false,
                mess: "DB Err",
            });
        }

        if (user.data.length === 0) {
            return res.status(404).json({
                status: false,
                mess: "Invalid or expired token",
            });
        }

        const userFormat = [
            {
                id_: user.data[0].id_,
                username_: user.data[0].username_,
                email_: user.data[0].email_,
                full_name_: user.data[0].full_name_,
                phone_: user.data[0].phone_,
                address_: user.data[0].address_,
                avatar_: user.data[0].avatar_,
                rolename_: user.data[0].rolename_,
                permission_: JSON.parse(JSON.stringify(user.data[0].permission_)),
                status_: user.data[0].status_
            }
        ]
        req.user = userFormat;
        next();
    } catch (error) {
        console.log(error);
        return res.status(401).json({
            status: false,
            msg: "Missing token!"
        })
    }
}

module.exports = verify;