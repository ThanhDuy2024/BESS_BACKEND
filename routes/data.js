const router = require("express").Router();
const apiData = require("./dataProcess");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const sendOtpNodemailer = require("../models/nodemailer");
const verify = require("../models/verifyToken");
const cache = require("../models/cache");
router.get("/", (req, res) => {
  res.status(200).json({ message: "REST APIs is working" });
});

router.post("/getModbusTemp", async (req, res) => {
  let temp = await apiData.funcTable(
    "func_getmodbustemp",
    `('${req.body.sn}')`,
  );
  if (temp.status) {
    return res.status(200).json({
      status: true,
      data: temp.data,
    });
  }

  return res.status(500).json({
    status: false,
    mess: "DB Err",
  });
});

router.post("/login", async (req, res) => {
  try {
    const { account, password } = req.body;
    const result = await apiData.funcTable("func_loginUser", `('${account}')`);

    if (!result.status || result.data.length === 0) {
      return res.status(401).json({ status: false, mess: "Login failed" });
    }

    const user = result.data[0];

    if (!user.status_) {
      return res.status(401).json({ status: false, mess: "Account is locked" });
    }

    const isMatch = await bcrypt.compare(password, user.password_);
    if (!isMatch) {
      return res.status(401).json({ status: false, mess: "Login failed" });
    }

    const token = jwt.sign(
      {
        id: user.id_,
        username: user.username_,
        role: user.role_,
      },
      process.env.JWT_SECRET,
      { expiresIn: "30d" }
    );

    delete user.password_;

    return res.status(200).json({
      status: true,
      mess: "Login successful",
      token,
      data: user,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ status: false, mess: "System Err" });
  }
});

router.post("/getAllUser", verify, async (req, res) => {
  try {
    const user = await apiData.funcTable("func_getalluser", `() `);
    return res.status(200).json(user);
  } catch (error) {
    console.log(error);
    return res.status(401).json({
      status: false,
      mess: "Invalid token",
    });
  }
});

router.post("/getUser", verify, async (req, res) => {
  try {
    return res.status(200).json(req.user);
  } catch (error) {
    console.log(error);
    return res.status(401).json({
      status: false,
      mess: "Invalid token",
    });
  }
});

router.post("/updateUser", verify, async (req, res) => {
  try {

    if (req.body.action === "insert") {
      const { action, id, name, email, password, role, status, username } = req.body
      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(password, salt);

      const dbResponse = await apiData.funcTable(
        `func_insertuser`,
        `(
          '${username}',
          '${email}',
          '${hash}',
          '${name}', 
          '${role}',
          ${status === "active" ? true : false}
        )`
      )
      if (dbResponse.data[0].func_insertuser == false) {
        return res.status(400).json({
          status: false,
          mess: "Your email existed!"
        })
      } else {
        res.status(200).json({
          status: true,
          mess: "User insert successfully!"
        })
      }
    } else if (req.body.action === "update") {
      const dbResponse = await apiData.funcTable('func_updateuser',
        `(
          ${req.body.id},
          '${req.body.name}',
          '${req.body.username}',
          '${req.body.email}', 
          '${req.body.role}',
          ${req.body.status == 'true' ? true : false}
      )`)

      if (dbResponse.data[0].func_updateuser == false) {
        return res.status(400).json({
          status: false,
          mess: "Your email existed!"
        })
      } else {
        res.status(200).json({
          status: true,
          mess: "User insert successfully!"
        })
      }
    } else if (req.body.action === "updateStatus") {
      const dbResponse = await apiData.funcTable('func_updatestatususer',
        `(
          ${req.body.id},
          ${req.body.status === 'true' ? false : true}
        )`
      )

      if (dbResponse.data[0].func_updatestatususer == false) {
        return res.status(400).json({
          status: false,
          mess: "error database!"
        })
      } else {
        res.status(200).json({
          status: true,
          mess: "Status update successfully!"
        })
      }
    } else if (req.body.action === "delete") {
      const dbResponse = await apiData.funcTable('func_deleteuser',
        `(
          ${req.body.id}
        )`
      )

      if (dbResponse.data[0].func_deleteuser == false) {
        return res.status(400).json({
          status: false,
          mess: "error database!"
        })
      } else {
        res.status(200).json({
          status: true,
          mess: "User delete successfully!"
        })
      }
    }

  } catch (error) {
    console.log(error);
    res.status(401).json({
      status: false,
      mess: "Invalid token"
    })
  }
})

router.post("/renderOtp", async (req, res) => {
  try {
    const dbResponse = await apiData.funcTable('func_verifyemail',
      `(
        '${req.body.email}'
      )`
    )
    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    }

    if (dbResponse.data[0].func_verifyemail === false) {
      return res.status(404).json({
        status: false,
        msg: "Email not found!"
      })
    }

    //random digit
    const digit = Math.floor(100000 + Math.random() * 900000);
    //convert string
    const otp = String(digit);

    cache.set(otp, req.body.email);

    sendOtpNodemailer(req.body.email, otp);
    res.status(200).json({
      status: true,
      msg: "Otp sent successfully!"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
})

router.post("/verifyOtp", async (req, res) => {
  try {
    console.log(req.body);
    const email = cache.get(req.body.otp);
    console.log(email);
    if (!email) {
      return res.status(400).json({
        status: false,
        msg: "Invalid Otp!"
      })
    }
    res.status(200).json({
      status: true,
      msg: "Confirmed successfully!",
      email: email
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
})

router.post("/changePasswordWithOtp", async (req, res) => {
  try {
    const email = req.body.email;

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(req.body.password, salt);

    const changePassword = await apiData.funcTable('func_changepassword',
      `(
        '${email}',
        '${hash}'
      )`
    );

    if (changePassword.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    }

    if (changePassword.data[0].func_changepassword === false) {
      return res.status(404).json({
        status: false,
        msg: "Action invalid!"
      })
    }

    res.status(200).json({
      status: true,
      msg: "Change password successfully!"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
})

router.post("/changePassword", verify, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const dbResponse = await apiData.funcTable('func_checkpassword', 
      `(
        ${req.user.data[0].id_}
      )`
    );

    if(dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    }

    if(dbResponse.data.length === 0) {
      return res.status(404).json({
        status: false,
        msg: "User not found!"
      })  
    }

    const compare = bcrypt.compareSync(oldPassword, dbResponse.data[0].func_checkpassword);

    if(!compare) {
      return res.status(400).json({
        status: false,
        msg: "Your old password incorrect!"
      })    
    }

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(newPassword, salt);
    apiData.funcTable('func_changepassword',
      `(
        '${req.user.data[0].email_}',
        '${hash}'
      )`
    )


    res.status(200).json({
      status: true,
      msg: "Change password successfuly"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
})
module.exports = router;