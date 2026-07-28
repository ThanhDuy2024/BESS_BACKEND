const router = require("express").Router();
const data = require("./dataProcess");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const sendOtpNodemailer = require("../models/nodemailer");
const verify = require("../models/verifyToken");
const XlsxPopulate = require('xlsx-populate');
const cache = require("../models/core").cache;
const funcPagination = require("../models/core").funcPagination;
const capitalizeFirstLetter = require("../models/core").capitalizeFirstLetter;
const formatDate = require('../models/core').formatDate;
const { format } = require('date-and-time');
const { assign } = require("nodemailer/lib/shared");
const mongo = require("../models/db_models");
const { upload } = require("../models/core");
const limit = 10;

router.get("/", (req, res) => {
  res.status(200).json({ message: "REST APIs is working" });
});

router.post("/getModbusTemp", async (req, res) => {
  let temp = await data.funcTable(
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

//Login and get users
router.post("/login", async (req, res) => {
  try {
    const { account, password } = req.body;
    const result = await data.funcTable("func_loginUser", `('${account}')`);
    if (!result.status || result.data.length === 0) {
      return res.status(401).json({ status: false, mess: "Login failed" });
    }

    const user = result.data[0];

    if (user.status_ === "locked" || user.status_ === "deleted") {
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
        role: user.rolename_,
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

router.get("/getUser", verify, async (req, res) => {
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
//End login and get users

//forgot password
router.post("/renderOtp", async (req, res) => {
  try {
    const dbResponse = await data.funcTable('func_verifyemail',
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
    const html = `Mã OTP của bạn là: <b>${otp}</b> <div>Lưu ý mã OTP chỉ có hiệu lực trong vòng 1 phút</div>`
    sendOtpNodemailer(req.body.email, otp, html);

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
});

router.post("/verifyOtp", async (req, res) => {
  try {
    const email = cache.get(req.body.otp);
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
});

router.post("/changePasswordWithOtp", async (req, res) => {
  try {
    const email = req.body.email;

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(req.body.password, salt);

    const changePassword = await data.funcTable('func_changepassword',
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
});
//End forgot password

//change password and change user infor
router.post("/changePassword", verify, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    if (req.user.data[0].id_ === 8) {
      return res.status(400).json({
        status: false,
        msg: "You not permission in action"
      })
    }

    const dbResponse = await data.funcTable('func_checkpassword',
      `(
        ${req.user.data[0].id_}
      )`
    );

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    }

    if (dbResponse.data.length === 0) {
      return res.status(404).json({
        status: false,
        msg: "User not found!"
      })
    }

    const compare = bcrypt.compareSync(oldPassword, dbResponse.data[0].func_checkpassword);

    if (!compare) {
      return res.status(400).json({
        status: false,
        msg: "Your old password incorrect!"
      })
    }

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(newPassword, salt);
    data.funcTable('func_changepassword',
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
});

router.post("/changeUserInfo", verify, async (req, res) => {
  try {
    const { action, value, address } = req.body;
    const actionFormat = action.toLowerCase();
    console.log(actionFormat);
    if (actionFormat !== "name" && actionFormat !== "email" && actionFormat !== "phone" && actionFormat !== "address") {
      return res.status(400).json({
        status: false,
        msg: "Error action"
      })
    };

    const userId = req.user.data[0].id_;
    if (userId === 50) {
      return res.status(400).json({
        status: false,
        msg: "No permission"
      })
    };

    const dbResponse = await data.funcTable('func_changeuserinfo',
      `(
        '${actionFormat}',
        '${value}',
        ${userId}
      )`
    )

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "error db!"
      })
    };

    if (dbResponse.data[0].func_changeuserinfo === false) {
      return res.status(400).json({
        status: false,
        msg: "Your email existed!"
      })
    };

    res.status(200).json({
      status: true,
      msg: "Change info success!"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Change info error"
    })
  }
});
//end change password and change user infor

//User management logic
router.post("/renderOtpWhenCreateUser", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission.users) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission.users.includes('create')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const { email } = req.body;

    //random digit
    const digit = Math.floor(100000 + Math.random() * 900000);
    //convert string
    const otp = String(digit);

    const dbResponse = await data.funcTable('func_verifyemailotp',
      `(
        '${email}'
      )`
    );

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db"
      })
    };

    if (dbResponse.data[0].func_verifyemailotp === false) {
      return res.status(400).json({
        status: false,
        msg: "Your email or username existed!"
      })
    }

    cache.set(otp, email);
    const html = `Mã OTP kích hoạt tài khoản của bạn là: <b>${otp}</b> <div>Lưu ý mã OTP chỉ có hiệu lực trong vòng 1 phút</div>`
    sendOtpNodemailer(email, otp, html);

    res.status(200).json({
      status: true,
      msg: "Send otp successful"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
});

router.post("/createUser", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission.users) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission.users.includes('create')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const checkOtp = cache.get(req.body.otp);

    if (!checkOtp) {
      return res.status(400).json({
        status: false,
        msg: "Otp expire"
      })
    };

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(req.body.password, salt);
    const dbResponse = await data.funcTable(
      `func_insertuser`,
      `('${req.body.username}', '${req.body.email}', '${hash}', '${req.body.name}', ${req.body.roleId}, '${req.body.status}')`
    )

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db"
      })
    };

    if (dbResponse.data[0].func_insertuser == false) {
      return res.status(400).json({
        status: false,
        msg: "Your email or username existed!"
      })
    }

    res.status(200).json({
      status: true,
      msg: "User has created!"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

router.get("/getAllUser", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission.users) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission.users.includes('read')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const user = await data.funcTable("func_getalluser", `()`);
    return res.status(200).json(user);
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
    const permission = req.user[0].permission_;

    if (!permission.users) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission.users.includes('update')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const dbResponse = await data.funcTable('func_updateuser',
      `(
        ${req.body.userId},
        '${req.body.fullName}',
        ${req.body.roleId},
        '${req.body.status}'
      )`
    )

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    };

    if (dbResponse.data[0].func_updateuser === "error user") {
      return res.status(404).json({
        status: false,
        msg: "User not found"
      })
    };

    if (dbResponse.data[0].func_updateuser === "error role") {
      return res.status(404).json({
        status: false,
        msg: "Role not found"
      })
    };

    res.status(200).json({
      status: true,
      msg: "User has updated!"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

router.post("/deleteUser", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission.users) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission.users.includes('delete')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };
    const { userId } = req.body;
    const dbResponse = await data.funcTable('func_deleteuser',
      `(
        ${userId}
      )`
    );

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    };

    if (dbResponse.data[0].func_deleteuser === false) {
      return res.status(404).json({
        status: false,
        msg: "User not found!"
      })
    };

    res.status(200).json({
      status: true,
      msg: "User has deleted!"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

router.get("/recoveryList", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission.users) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission.users.includes('recovery')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const filter = {
      search: '',
      sort: 'id'
    };

    if (req.query.search) {
      filter.search = req.query.search;
    } else {
      filter.search = '';
    }

    if (req.query.sort) {
      filter.sort = req.query.sort.toLowerCase();
    }

    const totalRecord = await data.funcTable('func_totalrecoveryuser', `('${filter.search === 'undefined' ? '' : filter.search}')`);

    if (totalRecord.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    };

    const totalUserRecovery = totalRecord.data[0].func_totalrecoveryuser;
    let pagination = {}
    if (req.query.page) {
      pagination = funcPagination(req.query.page, limit, totalUserRecovery);
    } else {
      pagination = funcPagination(1, limit, totalUserRecovery);
    };

    const dbResponse = await data.funcTable('func_getallrecoveryuser',
      `(
        '${filter.search}',
        '${filter.sort}',
        ${pagination.offset},
        ${limit}
      )`
    );

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    };

    const recovery = dbResponse.data;
    const data_ = [];
    for (const item of recovery) {
      const rawData = {
        id: item.id_,
        fullName: item.full_name_,
        username: item.username_,
        email: item.email_,
        roleId: item.roleid_,
        roleName: capitalizeFirstLetter(item.rolename_),
        status: item.status_,
        deletedAt: format(item.deleted_at_, "HH:mm DD/MM/YYYY"),
      }
      data_.push(rawData);
    }
    res.status(200).json({
      status: true,
      data: data_,
      totalPage: pagination.totalPage
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

router.post("/recovery", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission.users) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission.users.includes('recovery')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const dbResponse = await data.funcTable('func_recoveryUser',
      `(
        ${req.body.userId}
      )`
    );

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    };

    if (dbResponse.data[0].func_recoveryUser === false) {
      return res.status(404).json({
        status: false,
        msg: "User not found"
      })
    };

    res.status(200).json({
      status: true,
      msg: "Recovery successful!"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

//new api delete user recovery
router.post("/deleteUserRecovery", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission.users) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission.users.includes('recovery')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const { userId } = req.body;
    const dbResponse = await data.funcTable('func_deleteuserrecovery',
      `(
        ${userId}
      )`
    );

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    };

    if (dbResponse.data[0].func_deleteuserrecovery === false) {
      return res.status(404).json({
        status: false,
        msg: "User not found!"
      })
    };

    res.status(200).json({
      status: true,
      msg: "Delete user successful!"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});
//End User management logic

//Logic role and permission
router.post("/createRole", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission.roles) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission.roles.includes('create')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const { roleName, status } = req.body;
    const roleNameFormat = roleName.toLowerCase();
    const dbResponse = await data.funcTable('func_insertrole',
      `(
        '${roleNameFormat}',
        '${status}',
        ${req.user.data[0].id_}
      )`
    );

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db"
      })
    };

    if (dbResponse.data[0].func_insertrole == false) {
      return res.status(400).json({
        status: false,
        msg: "Role name existed!"
      })
    }

    res.status(200).json({
      status: true,
      msg: "Role has created!"
    });
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

router.get("/getAllRoles", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission.roles) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission.roles.includes('read')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const filter = {
      search: "",
      status: "",
      sort: "id"
    };

    if (req.query.search) {
      filter.search = req.query.search;
    };

    if (req.query.status) {
      filter.status = req.query.status
    }

    if (req.query.sort) {
      filter.sort = req.query.sort;
    }

    const totalRecord = await data.funcTable('func_totalrole', `('${filter.search}', '${filter.status}')`);

    if (totalRecord.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db"
      })
    };

    const totalRole = totalRecord.data[0].func_totalrole;

    let pagination = {};
    if (req.query.page) {
      pagination = funcPagination(req.query.page, limit, totalRole);
    } else {
      pagination = funcPagination(1, limit, totalRole);
    };

    const dbResponse = await data.funcTable('func_getallrole',
      `(
        ${pagination.offset},
        ${limit},
        '${filter.search}',
        '${filter.status}',
        '${filter.sort}'
      )`
    );

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db"
      })
    };

    const data_ = [];
    for (const item of dbResponse.data) {
      const rawData = {
        id: item.id_,
        roleName: capitalizeFirstLetter(item.rolename_),
        status: item.status_,
        createdBy: item.username_,
        createdAt: format(item.timestamp_, "HH:mm DD/MM/YYYY"),
        numberOfUser: item.totaluser
      };
      if (req.query.status) {
        if (req.query.status === rawData.status) {
          data.push(rawData);
        }
      } else {
        data_.push(rawData);
      }
    }

    res.status(200).json({
      status: true,
      data: data_,
      totalPage: pagination.totalPage
    });
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

router.post("/deleteRole", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission.roles) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission.roles.includes('delete')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const { roleId } = req.body;
    const dbResponse = await data.funcTable('func_deleterole',
      `(
        ${roleId}
      )`
    );
    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    }
    if (dbResponse.data[0].func_deleterole === false) {
      return res.status(400).json({
        status: false,
        msg: "Role not found!"
      })
    }
    res.status(200).json({
      status: true,
      msg: "Role has deleted!"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

router.get("/roleDetail/:id", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission.roles) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission.roles.includes('read')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const dbResponse = await data.funcTable('func_getrole', `(${req.params.id})`);

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: 'Error db'
      })
    };

    if (!dbResponse.data[0]) {
      return res.status(404).json({
        status: false,
        msg: 'Role not found!'
      })
    };

    const role = {
      id: dbResponse.data[0].id_,
      roleName: dbResponse.data[0].rolename_,
      status: dbResponse.data[0].status_,
      permission: JSON.parse(JSON.stringify(dbResponse.data[0].permission_))
    };

    return res.status(200).json({
      status: true,
      data: role,
    })
  } catch (error) {
    console.log(error);
    return res.status(404).json({
      status: false,
      message: "Role not found!"
    })
  }
});

router.post("/roleUpdate", verify, async (req, res) => {
  try {
    const permissiondb = req.user[0].permission_;

    if (!permissiondb.roles) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permissiondb.roles.includes('update')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const { id, roleName, status, permission } = req.body;

    const dbResponse = await data.funcTable('func_updaterole',
      `(
        ${id},
        '${roleName}',
        '${status}', 
        '${JSON.stringify(permission)}'
      )`
    );

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: 'Error db'
      })
    };

    if (dbResponse.data[0].func_updaterole === false) {
      return res.status(400).json({
        status: false,
        msg: 'Role not found!'
      })
    };

    return res.status(200).json({
      status: true,
      msg: "Role has updated!"
    })
  } catch (error) {
    console.log(error);
    return res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});
//End role and permission 

//Report logic
router.post("/calculate", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["energy-report"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["energy-report"].includes('read')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const { date } = req.body;

    const formattedDate = formatDate(date);

    const dbResponse = await mongo.History.findOne({
      deviceid: "N150FL4L2C072590",
      date: formattedDate
    });
    if (!dbResponse) {
      return res.status(400).json({
        status: false,
        msg: 'Error db'
      })
    };

    const scale = await mongo.Report.findOne({
      deviceid: "N150FL4L2C072590"
    })

    const scaleCharge = scale.register[6].scale;
    const scaleDischarge = scale.register[7].scale;

    const charge = Number((dbResponse.result[dbResponse.result.length - 1][7] * scaleCharge).toFixed(2));
    const discharge = Number((dbResponse.result[dbResponse.result.length - 1][8] * scaleCharge).toFixed(2));

    return res.status(200).json({
      status: true,
      msg: "Successful",
      data: {
        charge: charge,
        discharge: discharge
      }
    })

  } catch (error) {
    console.log(error);
    return res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

router.post("/getAllReport", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["energy-report"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["energy-report"].includes('read')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const { date } = req.body;

    const [day, month, year] = date.split("/");

    const formattedDate = formatDate(date);

    const dbResponse = await mongo.History.findOne(
      { deviceid: "N150FL4L2C072590", date: formattedDate }
    );

    if (!dbResponse) {
      return res.status(400).json({
        status: false,
        msg: 'Error db'
      })
    };

    const reports = await mongo.Report.findOne({
      deviceid: "N150FL4L2C072590"
    });

    let scale = {};
    for (const item of reports.register) {
      scale = {
        ...scale,
        [item.id]: Number(item.scale),
      }
    };

    const arrayData = []
    for (const Item1 of dbResponse.result) {
      const [time, soc, soh, volt, current, grid, load, charge, discharge] = Item1;
      const obj = { time, soc, soh, volt, current, grid, load, charge, discharge };
      obj.soc = Number(obj.soc);
      obj.soh = Number(obj.soh);
      obj.volt = Number(Number(obj.volt) * scale["E3"]).toFixed(2);
      obj.current = Number(Number(obj.current) * scale["E4"]).toFixed(2);
      obj.grid = Number(Number(obj.grid) * scale["E5"]).toFixed(2);
      obj.load = Number(Number(obj.load) * scale["E6"]).toFixed(2);
      obj.charge = Number(Number(obj.charge) * scale["E7"]).toFixed(2);
      obj.discharge = Number(Number(obj.discharge) * scale["E8"]).toFixed(2);
      arrayData.push(obj);
    }

    return res.status(200).json({
      status: true,
      msg: "Successful",
      data: arrayData
    })
  } catch (error) {
    console.log(error)
    return res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

router.get("/getAllReportPagination", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["energy-report"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["energy-report"].includes('read')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };
    const date = req.query.date;
    const [day, month, year] = date.split("/");
    const formattedDate = `${month}/${day}/${year}`;

    const page = Number(req.query.page) || 1;

    const dbResponse = await mongo.History.findOne(
      { date: formattedDate },
    )

    const total = dbResponse.result.length;

    let pagination = {};
    if (req.query.page) {
      pagination = funcPagination(req.query.page, limit, total);
    } else {
      pagination = funcPagination(1, limit, total);
    };

    const pageData = dbResponse.result.reverse().slice(pagination.offset, pagination.offset + limit);

    if (!dbResponse) {
      return res.status(400).json({
        status: false,
        msg: 'Error db'
      })
    };

    const arrayData = []
    for (const Item1 of pageData) {
      const [time, soc, soh, volt, current, grid, load, charge, discharge, totalCharge, totalDischarge] = Item1;
      const obj = { time, soc, soh, volt, current, grid, load, charge, discharge, totalCharge, totalDischarge };
      obj.soc = Number(obj.soc);
      obj.soh = Number(obj.soh);
      obj.volt = Number(obj.volt).toFixed(2);
      obj.current = Number(obj.current).toFixed(2);
      obj.grid = Number(obj.grid).toFixed(2);
      obj.load = Number(obj.load).toFixed(2);
      obj.charge = Number(obj.charge).toFixed(2);
      obj.discharge = Number(obj.discharge).toFixed(2);
      arrayData.push(obj);
    }

    return res.status(200).json({
      status: true,
      msg: "Successful",
      data: arrayData,
      totalPage: pagination.totalPage
    })
  } catch (error) {
    console.log(error)
    return res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

router.post("/export-excel-today", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["energy-report"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["energy-report"].includes('read')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };
    const date = req.body.date;
    const newDate = formatDate(date);
    const reports = await mongo.Report.findOne({
      deviceid: "N150FL4L2C072590"
    });

    //E7
    const chargePerHoursScale = reports.register[6].scale;
    //E8
    const dischargePerHoursScale = reports.register[7].scale;

    const history = await mongo.History.findOne({
      deviceid: "N150FL4L2C072590",
      date: newDate
    });

    const chargePerHoursHistory = history.result[history.result.length - 1][7];
    const dischargePerHoursHistory = history.result[history.result.length - 1][8];

    const obj = {
      totalChargeToDay: (Number(chargePerHoursHistory) * Number(chargePerHoursScale)).toFixed(2),
      totalDischargeToDay: (Number(dischargePerHoursHistory) * Number(dischargePerHoursScale)).toFixed(2),
      arrayData: []
    }

    let scale = {};
    for (const item of reports.register) {
      scale = {
        ...scale,
        [item.id]: Number(item.scale)
      }
    };

    for (const item of history.result) {
      const [time, soc, soh, volt, current, grid, load, charge, discharge] = item;
      const tmpObj = { time, soc, soh, volt, current, grid, load, charge, discharge }
      tmpObj.soc = Number(tmpObj.soc);
      tmpObj.soh = Number(tmpObj.soh);
      tmpObj.volt = (Number(tmpObj.volt) * scale["E3"]);
      tmpObj.current = (Number(tmpObj.current) * scale["E4"]);
      tmpObj.grid = (Number(tmpObj.grid) * scale["E5"]);
      tmpObj.load = (Number(tmpObj.load) * scale["E6"]);
      tmpObj.charge = (Number(tmpObj.charge) * scale["E7"]);
      tmpObj.discharge = (Number(tmpObj.discharge) * scale["E8"]);
      obj.arrayData.push(tmpObj)
    }

    const workbook = await XlsxPopulate.fromBlankAsync();
    const sheet = workbook.sheet(0);

    sheet.range("A1:I1")
      .merged(true)
      .value(`BÁO CÁO NGÀY ${date}`)
      .style({
        bold: true,
        fontSize: 18,
        horizontalAlignment: "center",
        verticalAlignment: "center",
      });

    sheet.cell("A2").value("Tổng lượng sạc hôm nay").style({ bold: true });
    sheet.cell("B2").value(Number(obj.totalChargeToDay));
    sheet.cell("A3").value("Tổng lượng xả hôm nay").style({ bold: true });
    sheet.cell("B3").value(Number(obj.totalDischargeToDay));

    const headers = [
      "Thời gian (Time)",
      "SOC",
      "SOH",
      "Điện áp (Voltage)",
      "Dòng điện (Current)",
      "Lượng sạc từ lưới điện (Grid)",
      "Xả vào tải (Load)",
      "Sản lượng sạc (Charge)",
      "Sản lượng xả (Discharge)",
    ];

    headers.forEach((header, index) => {
      sheet
        .cell(6, index + 1)
        .value(header)
        .style({
          bold: true,
          fill: "D9EAD3",
          horizontalAlignment: "center",
        });
    });

    obj.arrayData.forEach((item, rowIndex) => {
      const row = rowIndex + 7;

      sheet.cell(row, 1).value(item.time);
      sheet.cell(row, 2).value(item.soc);
      sheet.cell(row, 3).value(item.soh);
      sheet.cell(row, 4).value(item.volt);
      sheet.cell(row, 5).value(item.current);
      sheet.cell(row, 6).value(item.grid);
      sheet.cell(row, 7).value(item.load);
      sheet.cell(row, 8).value(item.charge);
      sheet.cell(row, 9).value(item.discharge);
    });

    // Tự động chỉnh độ rộng cột
    sheet.column("A").width(25);
    sheet.column("B").width(10);
    sheet.column("C").width(10);
    sheet.column("D").width(20);
    sheet.column("E").width(20);
    sheet.column("F").width(30);
    sheet.column("G").width(20);
    sheet.column("H").width(23);
    sheet.column("I").width(30);

    //await workbook.toFileAsync("./excel/Battery_Report_ToDay.xlsx");

    const buffer = await workbook.outputAsync();

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );

    res.setHeader(
      "Content-Disposition",
      'attachment; filename="Battery_Report_ToDay.xlsx"'
    );

    res.send(buffer);
  } catch (error) {
    console.log(error);
    res.status(400).json({
      code: "error",
      msg: "Bad request"
    })
  }
});
//End report logic

//Upload avatar 
router.post("/uploadAvatar", verify, upload.single("avatar"), async (req, res) => {
  try {
    const linkImage = `http://bess2.local:3001/uploads/user/${req.file.originalname}`
    console.log(linkImage)
    const userId = req.user[0].id_;
    const dbResponse = await data.funcTable('func_updateavt',
      `(
        ${userId},
        '${linkImage}'
      )`
    )

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "error db!"
      })
    };

    res.status(200).json({
      status: true,
      msg: "Update Avatar Success"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Update Avatar Error"
    })
  }

}
);
//End upload avatar

//BMS LOGIC
router.get("/getAllRackInfo", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["battery"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["battery"].includes('read')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const dbResponse = await data.funcTable('func_getallrackinfo', '()');

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "error db"
      })
    };
    res.status(200).json({
      status: true,
      data: dbResponse.data
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});
//end bms logic

//BMS management logic
//BMS rack logic
router.post("/createRack", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["bms"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["bms"].includes('create')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };
    const { rackName, model, brand } = req.body;

    const getAllRack = await data.funcTable('func_getallrack', `()`);

    if (getAllRack.status === false) {
      return res.status(400).json({
        status: false,
        msg: "error db"
      })
    };

    if (getAllRack.data.length === 0) {
      const startRackAddress = 100;
      const obj = {
        rackName: rackName,
        model: model,
        brand: brand,
        startRackAddress: startRackAddress,
        template: {
          status: {
            register: "100-1",
            scale: 0,
            offset: 0,
            type: "word"
          },

          voltage: {
            register: "115-1",
            scale: 0.1,
            offset: 0,
            type: "word"
          },

          current: {
            register: "116-1",
            scale: 0.1,
            offset: -3200,
            type: "word"
          },

          temperature: {
            register: "117-1",
            scale: 1,
            offset: -40,
            type: "word"
          },

          soc: {
            register: "118-1",
            scale: 1,
            offset: 0,
            type: "word"
          },

          soh: {
            register: "119-1",
            scale: 1,
            offset: 0,
            type: "word"
          },

          maximumCellVoltage: {
            register: "123-1",
            scale: 0.001,
            offset: 0,
            type: "word"
          },

          minimumCellVoltage: {
            register: "125-1",
            scale: 0.001,
            offset: 0,
            type: "word"
          },

          maximumCellTemperature: {
            register: "127-1",
            scale: 1,
            offset: -40,
            type: "word"
          },

          minimumCellTemperature: {
            register: "129-1",
            scale: 1,
            offset: -40,
            type: "word"
          },
        }
      }
      const createRack = await data.funcTable('func_createrack',
        `(
          '${obj.rackName}',
          '${obj.model}',
          '${obj.brand}',
          ${startRackAddress},
          '${JSON.stringify(obj.template)}'
        )`
      )

      if (createRack.status === false) {
        return res.status(400).json({
          status: false,
          msg: "error db",
        })
      };

      if (createRack.data[0].func_createrack === false) {
        return res.status(400).json({
          status: false,
          msg: "Rack name is existed!",
        })
      }
    } else if (getAllRack.data.length !== 0) {
      const startRackAddress = getAllRack.data[getAllRack.data.length - 1].start_rack_address_ + 3000;
      const obj = {
        rackName: rackName,
        model: model,
        brand: brand,
        startRackAddress: startRackAddress,
        template: {
          status: {
            register: `${startRackAddress}-1`,
            scale: 0,
            offset: 0,
            type: "word"
          },
          voltage: {
            register: `${startRackAddress + 15}-1`,
            scale: 0.1,
            offset: 0,
            type: "word"
          },
          current: {
            register: `${startRackAddress + 16}-1`,
            scale: 0.1,
            offset: -3200,
            type: "word"
          },
          temperature: {
            register: `${startRackAddress + 17}-1`,
            scale: 1,
            offset: -40,
            type: "word"
          },
          soc: {
            register: `${startRackAddress + 18}-1`,
            scale: 1,
            offset: 0,
            type: "word"
          },
          soh: {
            register: `${startRackAddress + 19}-1`,
            scale: 1,
            offset: 0,
            type: "word"
          },
          maximumCellVoltage: {
            register: `${startRackAddress + 23}-1`,
            scale: 0.001,
            offset: 0,
            type: "word"
          },

          minimumCellVoltage: {
            register: `${startRackAddress + 25}-1`,
            scale: 0.001,
            offset: 0,
            type: "word"
          },

          maximumCellTemperature: {
            register: `${startRackAddress + 27}-1`,
            scale: 1,
            offset: -40,
            type: "word"
          },

          minimumCellTemperature: {
            register: `${startRackAddress + 29}-1`,
            scale: 1,
            offset: -40,
            type: "word"
          },
        }
      };

      const createRack = await data.funcTable('func_createrack',
        `(
          '${obj.rackName}',
          '${obj.model}',
          '${obj.brand}',
          ${startRackAddress},
          '${JSON.stringify(obj.template)}'
        )`
      )

      if (createRack.status === false) {
        return res.status(400).json({
          status: false,
          msg: "error db",
        })
      };

      if (createRack.data[0].func_createrack === false) {
        return res.status(400).json({
          status: false,
          msg: "Rack name is existed!",
        })
      }
    }

    const getRackWhenCreated = await data.funcTable('func_getrackwhencreated', '()');

    if (getRackWhenCreated.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    }

    const rack = getRackWhenCreated.data[0];
    res.status(200).json({
      status: true,
      msg: "Rack has created!",
      data: rack
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

router.post("/v2/createRack", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["bms"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["bms"].includes('create')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const {
      rackName,
      model,
      brand,
      voltage,
      current,
      temperature,
      soc,
      soh,
      maximumCellVoltage,
      minimumCellVoltage,
      maximumCellTemperature,
      minimumCellTemperature,
    } = req.body;

    const getAllRack = await data.funcTable('func_getallrack', `()`);

    if (getAllRack.status === false) {
      return res.status(400).json({
        status: false,
        msg: "error db"
      })
    };

    if (getAllRack.data.length === 0) {
      const startRackAddress = 100;
      const obj = {
        rackName: rackName,
        model: model,
        brand: brand,
        startRackAddress: startRackAddress,
        template: {
          status: {
            register: "100-1",
            scale: 0,
            offset: 0,
            type: "word"
          },

          voltage: {
            register: "115-1",
            scale: voltage.scale,
            offset: voltage.offset,
            type: "word"
          },

          current: {
            register: "116-1",
            scale: current.scale,
            offset: current.offset,
            type: "word"
          },

          temperature: {
            register: "117-1",
            scale: temperature.scale,
            offset: temperature.offset,
            type: "word"
          },

          soc: {
            register: "118-1",
            scale: soc.scale,
            offset: soc.offset,
            type: "word"
          },

          soh: {
            register: "119-1",
            scale: soh.scale,
            offset: soh.offset,
            type: "word"
          },

          maximumCellVoltage: {
            register: "123-1",
            scale: maximumCellVoltage.scale,
            offset: maximumCellVoltage.offset,
            type: "word"
          },

          minimumCellVoltage: {
            register: "125-1",
            scale: minimumCellVoltage.scale,
            offset: minimumCellVoltage.offset,
            type: "word"
          },

          maximumCellTemperature: {
            register: "127-1",
            scale: maximumCellTemperature.scale,
            offset: maximumCellTemperature.offset,
            type: "word"
          },

          minimumCellTemperature: {
            register: "129-1",
            scale: minimumCellTemperature.scale,
            offset: minimumCellTemperature.offset,
            type: "word"
          },
        }
      }
      const createRack = await data.funcTable('func_createrack',
        `(
          '${obj.rackName}',
          '${obj.model}',
          '${obj.brand}',
          ${startRackAddress},
          '${JSON.stringify(obj.template)}'
        )`
      )

      if (createRack.status === false) {
        return res.status(400).json({
          status: false,
          msg: "error db",
        })
      };

      if (createRack.data[0].func_createrack === false) {
        return res.status(400).json({
          status: false,
          msg: "Rack name is existed!",
        })
      }
    } else if (getAllRack.data.length !== 0) {
      const startRackAddress = getAllRack.data[getAllRack.data.length - 1].start_rack_address_ + 3000;
      const obj = {
        rackName: rackName,
        model: model,
        brand: brand,
        startRackAddress: startRackAddress,
        template: {
          status: {
            register: `${startRackAddress}-1`,
            scale: 0,
            offset: 0,
            type: "word"
          },
          voltage: {
            register: `${startRackAddress + 15}-1`,
            scale: voltage.scale,
            offset: voltage.offset,
            type: "word"
          },
          current: {
            register: `${startRackAddress + 16}-1`,
            scale: current.scale,
            offset: current.offset,
            type: "word"
          },
          temperature: {
            register: `${startRackAddress + 17}-1`,
            scale: temperature.scale,
            offset: temperature.offset,
            type: "word"
          },
          soc: {
            register: `${startRackAddress + 18}-1`,
            scale: soc.scale,
            offset: soc.offset,
            type: "word"
          },
          soh: {
            register: `${startRackAddress + 19}-1`,
            scale: soh.scale,
            offset: soh.offset,
            type: "word"
          },
          maximumCellVoltage: {
            register: `${startRackAddress + 23}-1`,
            scale: maximumCellVoltage.scale,
            offset: maximumCellVoltage.offset,
            type: "word"
          },

          minimumCellVoltage: {
            register: `${startRackAddress + 25}-1`,
            scale: minimumCellVoltage.scale,
            offset: minimumCellVoltage.offset,
            type: "word"
          },

          maximumCellTemperature: {
            register: `${startRackAddress + 27}-1`,
            scale: maximumCellTemperature.scale,
            offset: maximumCellTemperature.offset,
            type: "word"
          },

          minimumCellTemperature: {
            register: `${startRackAddress + 29}-1`,
            scale: minimumCellTemperature.scale,
            offset: maximumCellTemperature.offset,
            type: "word"
          },
        }
      };

      const createRack = await data.funcTable('func_createrack',
        `(
          '${obj.rackName}',
          '${obj.model}',
          '${obj.brand}',
          ${startRackAddress},
          '${JSON.stringify(obj.template)}'
        )`
      )

      if (createRack.status === false) {
        return res.status(400).json({
          status: false,
          msg: "error db",
        })
      };

      if (createRack.data[0].func_createrack === false) {
        return res.status(400).json({
          status: false,
          msg: "Rack name is existed!",
        })
      }
    }

    const getRackWhenCreated = await data.funcTable('func_getrackwhencreated', '()');

    if (getRackWhenCreated.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    }

    const rack = getRackWhenCreated.data[0];
    res.status(200).json({
      status: true,
      msg: "Rack has created!",
      data: rack
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

router.get("/rackDetail/:id", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["bms"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["bms"].includes('read')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const { id } = req.params;

    const dbResponse = await data.funcTable('func_getrack', `(${id})`);

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db"
      })
    };

    if (dbResponse.data.length === 0) {
      return res.status(404).json({
        status: false,
        msg: "Rack not found!"
      })
    };

    res.status(200).json({
      status: true,
      data: dbResponse.data[0]
    });
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
});

router.post("/editRack", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["bms"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["bms"].includes('update')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const {
      rackId,
      rackName,
      model,
      brand,
      status,
      voltage,
      current,
      temperature,
      soc,
      soh,
      minimumCellVoltage,
      maximumCellVoltage,
      minimumCellTemperature,
      maximumCellTemperature
    } = req.body;

    const template = {
      status: status,
      voltage: voltage,
      current: current,
      temperature: temperature,
      soc: soc,
      soh: soh,
      maximumCellVoltage: maximumCellVoltage,
      minimumCellVoltage: minimumCellVoltage,
      maximumCellTemperature: maximumCellTemperature,
      minimumCellTemperature: minimumCellTemperature
    };

    const dbResponse = await data.funcTable('func_updaterack',
      `(
        ${rackId},
        '${rackName}',
        '${model}',
        '${brand}',
        '${JSON.stringify(template)}'
      )`
    );

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    };

    if (dbResponse.data[0].func_updaterack === false) {
      return res.status(400).json({
        status: false,
        msg: "Rack not found!"
      })
    };

    res.status(200).json({
      status: true,
      msg: "Edit successful"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
});

router.get("/getAllRack", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["bms"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["bms"].includes('read')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const dbResponse = await data.funcTable(`func_getAllRack`,
      `(
        '${req.query.createdAtFillter}', 
        '${req.query.addressFilter}',
        '${req.query.search}'
      )`
    );

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db"
      })
    };

    const racks = [];

    for (const item of dbResponse.data) {
      const tmp = {
        id_: item.id_,
        rack_name_: item.rack_name_,
        model_: item.model_,
        brand_: item.brand_,
        start_rack_address_: item.start_rack_address_,
        total_module_: item.total_module_,
        created_at_: format(item.created_at_, "DD/MM/YYYY")
      }
      racks.push(tmp);
    }

    res.status(200).json({
      status: true,
      data: racks
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
});
//End bms rack logic

//BMS module logic
router.post("/createModule", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["bms"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["bms"].includes('create')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const { rackId, moduleName, totalCells } = req.body;

    const getModule = await data.funcTable('func_getmodule',
      `(
        ${rackId}
      )`
    );

    if (getModule.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db"
      })
    };

    if (getModule.data.length === 0) {
      return res.status(404).json({
        status: false,
        msg: "Rack not found"
      })
    };

    if (getModule.data[getModule.data.length - 1].start_cell_address_ === null) {
      const startCellAddress = getModule.data[getModule.data.length - 1].start_rack_address_ + 91;
      const obj = {
        rackId: rackId,
        moduleName: moduleName,
        startCellAddress: startCellAddress,
        totalCells: totalCells,
        cells: [],
      }

      for (let i = startCellAddress; i <= (startCellAddress + totalCells) - 1; i++) {
        obj.cells.push({
          cellVoltage: {
            register: `${i}-1`,
            scale: 0.001,
            offset: 0,
            type: "word"
          },
          cellTemperature: {
            register: `${i + 700}-1`,
            scale: 1,
            offset: -40,
            type: "word"
          },
          cellSoc: {
            register: `${i + 700 + 700}-1`,
            scale: 1,
            offset: 0
          },
          cellSoh: {
            register: `${i + 700 + 700 + 700}-1`,
            scale: 1,
            offset: 0
          }
        })
      }
      const createModule = await data.funcTable('func_createmodule',
        `(
          ${obj.rackId},
          '${obj.moduleName}',
          ${obj.startCellAddress},
          ${obj.totalCells},
          '${JSON.stringify(obj.cells)}'
        )`
      )

      if (createModule.status === false) {
        return res.status(400).json({
          status: false,
          msg: "error db"
        })
      };

      if (createModule.data[0].func_createmodule === false) {
        return res.status(400).json({
          status: false,
          msg: "Module existed!"
        })
      }
    } else if (getModule.data[getModule.data.length - 1].start_cell_address_ !== null) {
      const module = getModule.data[getModule.data.length - 1]
      const startCellAddress = module.start_cell_address_ + module.total_cells_ + 1;

      const currentTotalCellInRack = await data.funcTable('func_totalcell',
        `(
          ${rackId}
        )`
      )
      const checkAddress = currentTotalCellInRack.data[0].func_totalcell + totalCells;

      if (checkAddress > 700) {
        return res.status(400).json({
          status: false,
          msg: "Cell full"
        })
      };

      const obj = {
        rackId: rackId,
        moduleName: moduleName,
        startCellAddress: startCellAddress,
        totalCells: totalCells,
        cells: [],
      }

      for (let i = startCellAddress; i <= (startCellAddress + totalCells) - 1; i++) {
        obj.cells.push({
          cellVoltage: {
            register: `${i}-1`,
            scale: 0.001,
            offset: 0,
            type: "word"
          },
          cellTemperature: {
            register: `${i + 700}-1`,
            scale: 1,
            offset: -40,
            type: "word"
          },
          cellSoc: {
            register: `${i + 700 + 700}-1`,
            scale: 1,
            offset: 0
          },
          cellSoh: {
            register: `${i + 700 + 700 + 700}-1`,
            scale: 1,
            offset: 0
          }
        });
      };

      const createModule = await data.funcTable('func_createmodule',
        `(
          ${obj.rackId},
          '${obj.moduleName}',
          ${obj.startCellAddress},
          ${obj.totalCells},
          '${JSON.stringify(obj.cells)}'
        )`
      )

      if (createModule.status === false) {
        return res.status(400).json({
          status: false,
          msg: "error db"
        })
      };

      if (createModule.data[0].func_createmodule === false) {
        return res.status(400).json({
          status: false,
          msg: "Module existed!"
        })
      }
    }

    res.status(200).json({
      status: true,
      msg: "Module has create!"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

router.post("/v2/createModule", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["bms"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["bms"].includes('create')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const { rackId, totalModules, totalCells } = req.body;
    const realTotalCell = 700;

    if (totalModules * totalCells > 700) {
      return res.status(400).json({
        status: false,
        msg: "Cell full"
      })
    }

    const getModule = await data.funcTable('func_getRack',
      `(
        ${rackId}
      )`
    );

    let startAddress = getModule.data[0].start_rack_address_ + 91;

    for (let i = 1; i <= totalModules; i++) {
      const obj = {
        rackId: rackId,
        moduleName: `Module 0${i}`,
        startCellAddress: startAddress,
        totalCells: totalCells,
        cells: [],
      }
      for (let j = startAddress; j <= startAddress + totalCells - 1; j++) {
        obj.cells.push({
          cellVoltage: {
            register: `${j}-1`,
            scale: 0.001,
            offset: 0,
            type: "word"
          },
          cellTemperature: {
            register: `${j + 700}-1`,
            scale: 1,
            offset: -40,
            type: "word"
          },
          cellSoc: {
            register: `${j + 700 + 700}-1`,
            scale: 1,
            offset: 0
          },
          cellSoh: {
            register: `${j + 700 + 700 + 700}-1`,
            scale: 1,
            offset: 0
          }
        });
      }
      startAddress = startAddress + totalCells + 1;
      const createModule = await data.funcTable('func_createmodule',
        `(
          ${obj.rackId},
          '${obj.moduleName}',
          ${obj.startCellAddress},
          ${obj.totalCells},
          '${JSON.stringify(obj.cells)}'
        )`
      )

      if (createModule.status === false) {
        return res.status(400).json({
          status: false,
          msg: "error db"
        })
      };
    }

    return res.status(200).json({
      status: true,
      msg: "Module has created!",
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
});

router.post("/v3/createModule", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["bms"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["bms"].includes('create')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };
    const { rackId, totalModules, totalCells, cellVoltage, cellTemperature, cellSoc, cellSoh } = req.body;
    const realTotalCell = 700;

    if (totalModules * totalCells > 700) {
      return res.status(400).json({
        status: false,
        msg: "Cell full"
      })
    }

    const getModule = await data.funcTable('func_getRack',
      `(
        ${rackId}
      )`
    );

    let startAddress = getModule.data[0].start_rack_address_ + 91;

    for (let i = 1; i <= totalModules; i++) {
      const obj = {
        rackId: rackId,
        moduleName: `Module 0${i}`,
        startCellAddress: startAddress,
        totalCells: totalCells,
        cells: [],
      }

      for (let j = startAddress; j <= startAddress + totalCells - 1; j++) {
        obj.cells.push({
          cellVoltage: {
            register: `${j}-1`,
            scale: cellVoltage.scale,
            offset: cellVoltage.offset,
            type: "word"
          },
          cellTemperature: {
            register: `${j + 700}-1`,
            scale: cellTemperature.scale,
            offset: cellTemperature.offset,
            type: "word"
          },
          cellSoc: {
            register: `${j + 700 + 700}-1`,
            scale: cellSoc.scale,
            offset: cellSoc.offset,
            type: "word"
          },
          cellSoh: {
            register: `${j + 700 + 700 + 700}-1`,
            scale: cellSoh.scale,
            offset: cellSoh.offset,
            type: "word"
          }
        });
      }

      startAddress = startAddress + totalCells + 1;
      const createModule = await data.funcTable('func_createmodule',
        `(
          ${obj.rackId},
          '${obj.moduleName}',
          ${obj.startCellAddress},
          ${obj.totalCells},
          '${JSON.stringify(obj.cells)}'
        )`
      )

      if (createModule.status === false) {
        return res.status(400).json({
          status: false,
          msg: "error db"
        })
      };
    }

    return res.status(200).json({
      status: true,
      msg: "Module has created!",
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
});

router.get("/moduleDetail/:id", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["bms"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["bms"].includes('read')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const { id } = req.params;

    const totalModuleAndTotalCells = await data.funcTable('func_getmoduledetail', `(${id})`);

    if (totalModuleAndTotalCells.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    };

    if (totalModuleAndTotalCells.data.length === 0) {
      return res.status(404).json({
        status: false,
        msg: "Module not found"
      })
    };

    const total = totalModuleAndTotalCells.data[0];

    const cells = await data.funcTable('func_getcells', `(${id})`);

    if (cells.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    };

    const template = cells.data[0].cells_[0];

    const dataRes = {
      total,
      template,
    }

    res.status(200).json({
      status: true,
      data: dataRes
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "bad request"
    })
  }
})

router.post("/editModule", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["bms"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["bms"].includes('update')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const {
      rackId,
      totalModules,
      totalCells
    } = req.body;

    const dbResponse = await data.funcTable('func_deletemodule', `(${rackId})`);

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db"
      })
    }

    if (dbResponse.data[0].func_deletemodule === false) {
      return res.status(404).json({
        status: false,
        msg: "Rack not found!"
      })
    }
    const realTotalCell = 700;

    if (totalModules * totalCells > 700) {
      return res.status(400).json({
        status: false,
        msg: "Cell full"
      })
    }

    const getModule = await data.funcTable('func_getRack',
      `(
        ${rackId}
      )`
    );

    let startAddress = getModule.data[0].start_rack_address_ + 91;

    for (let i = 1; i <= totalModules; i++) {
      const obj = {
        rackId: rackId,
        moduleName: `Module 0${i}`,
        startCellAddress: startAddress,
        totalCells: totalCells,
        cells: [],
      }
      for (let j = startAddress; j <= startAddress + totalCells - 1; j++) {
        obj.cells.push({
          cellVoltage: {
            register: `${j}-1`,
            scale: 0.001,
            offset: 0,
            type: "word"
          },
          cellTemperature: {
            register: `${j + 700}-1`,
            scale: 1,
            offset: -40,
            type: "word"
          },
          cellSoc: {
            register: `${j + 700 + 700}-1`,
            scale: 1,
            offset: 0
          },
          cellSoh: {
            register: `${j + 700 + 700 + 700}-1`,
            scale: 1,
            offset: 0
          }
        });
      }
      startAddress = startAddress + totalCells + 1;
      const createModule = await data.funcTable('func_createmodule',
        `(
          ${obj.rackId},
          '${obj.moduleName}',
          ${obj.startCellAddress},
          ${obj.totalCells},
          '${JSON.stringify(obj.cells)}'
        )`
      )

      if (createModule.status === false) {
        return res.status(400).json({
          status: false,
          msg: "error db"
        })
      };
    }

    res.status(200).json({
      status: true,
      msg: "Edit successful!"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
});

router.post("/v2/editModule", verify, async (req, res) => {
  try {
    const permission = req.user[0].permission_;

    if (!permission["bms"]) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    if (!permission["bms"].includes('update')) {
      return res.status(400).json({
        status: false,
        msg: "Not permission!"
      })
    };

    const {
      rackId,
      totalModules,
      totalCells,
      cellVoltage,
      cellTemperature,
      cellSoc,
      cellSoh
    } = req.body;

    console.log(req.body);

    const dbResponse = await data.funcTable('func_deletemodule', `(${rackId})`);

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db"
      })
    }

    if (dbResponse.data[0].func_deletemodule === false) {
      return res.status(404).json({
        status: false,
        msg: "Rack not found!"
      })
    }
    const realTotalCell = 700;

    if (totalModules * totalCells > 700) {
      return res.status(400).json({
        status: false,
        msg: "Cell full"
      })
    }

    const getModule = await data.funcTable('func_getRack',
      `(
        ${rackId}
      )`
    );

    let startAddress = getModule.data[0].start_rack_address_ + 91;

    for (let i = 1; i <= totalModules; i++) {
      const obj = {
        rackId: rackId,
        moduleName: `Module 0${i}`,
        startCellAddress: startAddress,
        totalCells: totalCells,
        cells: [],
      }
      for (let j = startAddress; j <= startAddress + totalCells - 1; j++) {
        obj.cells.push({
          cellVoltage: {
            register: `${j}-1`,
            scale: cellVoltage.scale,
            offset: cellVoltage.offset,
            type: "word"
          },
          cellTemperature: {
            register: `${j + 700}-1`,
            scale: cellTemperature.scale,
            offset: cellTemperature.offset,
            type: "word"
          },
          cellSoc: {
            register: `${j + 700 + 700}-1`,
            scale: cellSoc.scale,
            offset: cellSoc.offset,
            type: "word"
          },
          cellSoh: {
            register: `${j + 700 + 700}-1`,
            scale: cellSoh.scale,
            offset: cellSoh.offset,
            type: "word"
          },
        });
      }
      startAddress = startAddress + totalCells + 1;
      const createModule = await data.funcTable('func_createmodule',
        `(
          ${obj.rackId},
          '${obj.moduleName}',
          ${obj.startCellAddress},
          ${obj.totalCells},
          '${JSON.stringify(obj.cells)}'
        )`
      )

      if (createModule.status === false) {
        return res.status(400).json({
          status: false,
          msg: "error db"
        })
      };
    }

    res.status(200).json({
      status: true,
      msg: "Edit successful!"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
});
//End bms module logic
//End BMS management logic

//Alarm management logic
router.post("/createAlarm", verify, async (req, res) => {
  try {
    const { alarmLevel, alarmMessage, alarmAddress } = req.body;

    const dbResponse = await data.funcTable('func_createalarm', `(
      '${alarmLevel}',
      '${alarmMessage}',
      ${alarmAddress}  
    )`);

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    };

    if (dbResponse.data[0].func_createalarm === false) {
      return res.status(400).json({
        status: false,
        msg: "Alarm address is existed!"
      })
    };

    res.status(200).json({
      status: false,
      msg: "Alarm has created"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
})

router.post("/editAlarm", verify, async (req, res) => {
  try {
    const { alarmId, alarmLevel, alarmMessage } = req.body;

    const dbResponse = await data.funcTable('func_updatealarm',
      `(
        ${alarmId},
        '${alarmLevel}',
        '${alarmMessage}'
      )`
    );

    if (dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    };

    if (dbResponse.data[0].func_updatealarm === false) {
      return res.status(404).json({
        status: false,
        msg: "Alarm not found!"
      })
    };

    res.status(200).json({
      status: true,
      msg: "Alarm has edited"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
})

router.get("/getAllAlarmManagement", verify, async (req, res) => {
  try {
    const dbResponse = await data.funcTable('func_getallalarmmanagement', 
      `(
        '${req.query.createdAtFillter}',
        '${req.query.search}'
      )`
    );

    if(dbResponse.status === false) {
      return res.status(400).json({
        status: false,
        msg: "Error db!"
      })
    };

    const alarms = [];
    for (const item of dbResponse.data) {
      const temp = {
        id_: item.id_,
        level_: item.level_,
        message_: item.message_,
        address_: item.address_,
        created_at_: format(item.created_at_, "HH:mm DD/MM/YYYY")
      }
      alarms.push(temp)
    };

    res.status(200).json({
      status: true,
      data: alarms
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
})
//End alarm management logic
module.exports = router;