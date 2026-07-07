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
const { format } = require('date-and-time');
const { assign } = require("nodemailer/lib/shared");
const mongo = require("../models/db_models");
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
})

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
})

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
})
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
})

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
    if(userId === 50) {
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
})
//end change password and change user infor

//User management logic
router.post("/renderOtpWhenCreateUser", verify, async (req, res) => {
  try {
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
})

router.post("/getAllUser", verify, async (req, res) => {
  try {
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
})

router.post("/deleteUser", verify, async (req, res) => {
  try {
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
})

router.get("/recoveryList", verify, async (req, res) => {
  try {
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
})

router.post("/recovery", verify, async (req, res) => {
  try {
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
})

//new api delete user recovery
router.post("/deleteUserRecovery", verify, async (req, res) => {
  try {
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

    if(dbResponse.data[0].func_deleteuserrecovery === false) {
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
})
//End User management logic

//Logic role and permission
router.post("/createRole", verify, async (req, res) => {
  try {
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
})

router.get("/getAllRoles", verify, async (req, res) => {
  try {
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
})

router.post("/deleteRole", verify, async (req, res) => {
  try {
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
})

router.get("/roleDetail/:id", verify, async (req, res) => {
  try {
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
})
//End role and permission 

//Report logic
router.post("/calculate", verify, async (req, res) => {
  try {

    const { date } = req.body;

    const [day, month, year] = date.split("/");

    const formattedDate = `${month}/${day}/${year}`;

    const dbResponse = await mongo.History.findOne({
      date: formattedDate
    });
    if (!dbResponse) {
      return res.status(400).json({
        status: false,
        msg: 'Error db'
      })
    };

    const scale = await mongo.Report.findOne()

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
    const { date } = req.body;

    const [day, month, year] = date.split("/");

    const formattedDate = `${month}/${day}/${year}`;

    const dbResponse = await mongo.History.findOne(
      { date: formattedDate }
    );

    if (!dbResponse) {
      return res.status(400).json({
        status: false,
        msg: 'Error db'
      })
    };

    const arrayData = []
    for (const Item1 of dbResponse.result) {
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
      data: arrayData
    })
  } catch (error) {
    console.log(error)
    return res.status(400).json({
      status: false,
      msg: "Bad request!"
    })
  }
})

router.post("/excel", verify, async (req, res) => {
  try {
    const usersArray = [];
    const dbResponse = await data.funcTable('func_printexcel', `()`);

    for (const item of dbResponse.data) {
      const array = [
        item.id_,
        item.username_,
        item.full_name_,
        item.email_,
        item.phone_ === null ? "Null" : item.phone_,
        item.address_ === null ? "Null" : item.phone_,
        item.role_,
        item.status_
      ]

      usersArray.push(array);
    };

    XlsxPopulate.fromBlankAsync().then(workbook => {
      const sheet = workbook.sheet(0);
      const data = [
        ["Id", "User name", "Full Name", "Email", "Phone", "Address", "Role", "Status"],
        ...usersArray
      ];

      sheet.cell("A1").value(data);

      sheet.range("A1:H1").style({
        bold: true,
        fill: "4472C4",       // màu nền xanh
        fontColor: "FFFFFF",  // chữ trắng
        horizontalAlignment: "center"
      });

      sheet.range(`A2:A${2 + usersArray.length}`).style({
        bold: true
      })
      return workbook.toFileAsync("./excel/users.xlsx");
    })

    res.status(200).json({
      status: true,
      msg: "Excel is render"
    })
  } catch (error) {
    console.log(error);
    res.status(400).json({
      status: false,
      msg: "Bad request"
    })
  }
});
//End report logic
module.exports = router;