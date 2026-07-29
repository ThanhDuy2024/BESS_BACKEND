const joi = require("joi");

const loginValidate = (req, res, next) => {
    const schema = joi.object({
        account: joi.string().required()
            .messages({
                "string.empty": "v_login_account_empty",
            }),
        password: joi.string().required()
            .messages({
                "string.empty": "v_login_password_empty",
            })
    })

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message
        })
    }

    next();
}

// Forgort password validate
const renderOtpValidate = (req, res, next) => {
    const schema = joi.object({
        email: joi.string().email().required()
            .messages({
                "string.empty": "v_renderOtp_email_empty",
                "string.email": "v_renderOtp_email_error"
            }),
    });

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message,
        });
    }

    next();
}

const verifyOtpValidate = (req, res, next) => {
    const schema = joi.object({
        otp: joi.string().min(6).max(6).required()
            .messages({
                "string.empty": "v_verifyOtp_otp_empty",
                "string.min": "v_verifyOtp_otp_min_6",
                "string.max": "v_verifyOtp_otp_max_6"
            })
    })

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message
        })
    }

    next();
}

const changePasswordWithOtpValidate = (req, res, next) => {
    const schema = joi.object({
        email: joi.string().email().required()
            .messages({
                "string.empty": "v_changePasswordWithOtp_email_empty",
                "string.email": "v_changePasswordWithOtp_email_error"
            }),
        password: joi.string().required()
            .messages({
                "string.empty": "v_changePasswordWithOtp_password_empty",
            })
    });

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message
        })
    };

    next();
}
// End forgot password validate

//Change password in user info validate
const changePasswordValidate = (req, res, next) => {
    const schema = joi.object({
        oldPassword: joi.string().required()
            .messages({
                "string.empty": "v_changePassword_oldPassword_empty",
            }),
        newPassword: joi.string().required()
            .messages({
                "string.empty": "v_changePassword_newPassword_empty",
            })
    });

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message,
        })
    };

    next();
}
//End change password in user info validate

//User management logic
const renderOtpWhenCreateUserValidate = (req, res, next) => {
    const schema = joi.object({
        email: joi.string().email().required()
            .messages({
                "string.empty": "v_renderOtpWhenCreateUser_email_empty",
                "string.email": "v_renderOtpWhenCreateUser_email_error"
            }),
    });

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message,
        });
    }

    next();
}

const createUserValidate = (req, res, next) => {
    const schema = joi.object({
        otp: joi.string().min(6).max(6).required()
            .messages({
                "string.empty": "v_createUser_otp_empty",
                "string.min": "v_createUser_otp_min_6",
                "string.max": "v_createUser_otp_max_6"
            }),
        username: joi.string().min(8).pattern(/^[a-zA-Z0-9_]+$/).required()
            .messages({
                "string.empty": "v_createUser_username_empty",
                "string.min": "v_createUser_username_min_8",
                "string.pattern.base": "v_createUser_username_invalid"
            }),
        email: joi.string().email().required()
            .messages({
                "string.empty": "v_createUser_email_empty",
                "string.email": "v_createUser_email_error"
            }),
        password: joi.string().required()
            .messages({
                "string.empty": "v_createUser_password_empty",
            }),
        name: joi.string().min(8).required()
            .messages({
                "string.empty": "v_createUser_name_empty",
                "string.min": "v_createUser_name_min_8",
            }),
        roleId: joi.number().required()
            .messages({
                "any.empty": "v_createUser_roleId_empty"
            }),
        status: joi.string().required()
            .messages({
                "string.empty": "v_createUser_status_empty",
            }),
    })

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message,
        });
    }

    next();
}

const updateUserValidate = (req, res, next) => {
    const schema = joi.object({
        userId: joi.number().required()
            .messages({
                "any.empty": "v_updateUser_userId_empty"
            }),
        fullName: joi.string().min(8).required()
            .messages({
                "string.empty": "v_createUser_fullName_empty",
                "string.min": "v_createUser_fullName_min_8",
            }),
        roleId: joi.number().required()
            .messages({
                "any.empty": "v_updateUser_roleId_empty"
            }),
        status: joi.string().required()
            .messages({
                "string.empty": "v_updateUser_status_empty",
            }),
    })

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message,
        });
    }

    next();
}

const deleteUserValidate = (req, res, next) => {
    const schema = joi.object({
        userId: joi.number().required()
            .messages({
                "any.empty": "v_deleteUser_userId_empty"
            }),
    })

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message,
        });
    }

    next();
}

const recoveryAndDeleteUserRecoveryValidate = (req, res, next) => {
    const schema = joi.object({
        userId: joi.number().required()
            .messages({
                "any.empty": "v_recoveryAndDeleteUserRecovery_userId_empty"
            }),
    })

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message,
        });
    }

    next();
}
//End user management logic

//Role validate
const createRoleValidate = (req, res, next) => {
    const schema = joi.object({
        roleName: joi.string().required()
            .messages({
                "string.empty": "v_createRole_status_empty",
            }),
        status: joi.string().required()
            .messages({
                "string.empty": "v_createRole_status_empty",
            }),
    })

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message,
        });
    }

    next();

}

const deleteRoleValidate = (req, res, next) => {
    const schema = joi.object({
        roleId: joi.number().required()
            .messages({
                "any.empty": "v_deleteRole_roleId_empty"
            }),
    })

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message,
        });
    }

    next();
}

const updateRoleValidate = (req, res, next) => {
    const schema = joi.object({
        id: joi.number().required()
            .messages({
                "any.empty": "v_updateRole_roleId_empty"
            }),
        roleName: joi.string().required()
            .messages({
                "string.empty": "v_updateRole_status_empty",
            }),
        permisison: joi.required(),
        status: joi.string().required()
            .messages({
                "string.empty": "v_updateRole_status_empty",
            }),
    })

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message,
        });
    }

    next();
}
//End role validate

//Bms management validate
const createRackValidate = (req, res, next) => {
    const schema = joi.object({
        rackName: joi.string()
            .min(1)
            .pattern(/^[a-zA-Z0-9_]+$/)
            .required()
            .messages({
                "string.empty": "rack_name_not_empty",
                "string.pattern.base": "rack_name_invalid",
                "any.required": "rack_name_required"
            }),

        model: joi.string()
            .min(1)
            .pattern(/^[a-zA-Z0-9_]+$/)
            .required()
            .messages({
                "string.empty": "model_not_empty",
                "string.pattern.base": "model_invalid",
                "any.required": "model_required"
            }),

        brand: joi.string()
            .min(1)
            .pattern(/^[a-zA-Z0-9_]+$/)
            .required()
            .messages({
                "string.empty": "brand_not_empty",
                "string.pattern.base": "brand_invalid",
                "any.required": "brand_required"
            }),

        voltage: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        current: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        temperature: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        soc: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        soh: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        maximumCellVoltage: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        minimumCellVoltage: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        maximumCellTemperature: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        minimumCellTemperature: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required()
    });

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message
        });
    }
}

const editRackValidate = (req, res, next) => {
    const schema = joi.object({
        rackName: joi.string()
            .min(1)
            .pattern(/^[a-zA-Z0-9_]+$/)
            .required()
            .messages({
                "string.empty": "rack_name_not_empty",
                "string.pattern.base": "rack_name_invalid",
                "any.required": "rack_name_required"
            }),

        model: joi.string()
            .min(1)
            .pattern(/^[a-zA-Z0-9_]+$/)
            .required()
            .messages({
                "string.empty": "model_not_empty",
                "string.pattern.base": "model_invalid",
                "any.required": "model_required"
            }),

        brand: joi.string()
            .min(1)
            .pattern(/^[a-zA-Z0-9_]+$/)
            .required()
            .messages({
                "string.empty": "brand_not_empty",
                "string.pattern.base": "brand_invalid",
                "any.required": "brand_required"
            }),

        voltage: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        current: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        temperature: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        soc: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        soh: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        maximumCellVoltage: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        minimumCellVoltage: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        maximumCellTemperature: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        minimumCellTemperature: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required()
    });

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message
        });
    }
}

const createModuleValidate = (req, res, next) => {
    const schema = joi.object({
        rackId: joi.number()
            .integer()
            .positive()
            .required()
            .messages({
                "number.base": "rack_id_must_be_number",
                "number.integer": "rack_id_must_be_integer",
                "number.positive": "rack_id_must_be_positive",
                "any.required": "rack_id_required"
            }),

        totalModules: joi.number()
            .integer()
            .positive()
            .required()
            .messages({
                "number.base": "total_modules_must_be_number",
                "number.integer": "total_modules_must_be_integer",
                "number.positive": "total_modules_must_be_positive",
                "any.required": "total_modules_required"
            }),

        totalCells: joi.number()
            .integer()
            .positive()
            .required()
            .messages({
                "number.base": "total_cells_must_be_number",
                "number.integer": "total_cells_must_be_integer",
                "number.positive": "total_cells_must_be_positive",
                "any.required": "total_cells_required"
            }),

        cellVoltage: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        cellTemperature: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        cellSoc: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        cellSoh: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required()
    });

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message
        });
    }

    next();
};

const editModuleValidate = (req, res, next) => {
    const schema = joi.object({
        rackId: joi.number()
            .integer()
            .positive()
            .required()
            .messages({
                "number.base": "rack_id_must_be_number",
                "number.integer": "rack_id_must_be_integer",
                "number.positive": "rack_id_must_be_positive",
                "any.required": "rack_id_required"
            }),

        totalModules: joi.number()
            .integer()
            .positive()
            .required()
            .messages({
                "number.base": "total_modules_must_be_number",
                "number.integer": "total_modules_must_be_integer",
                "number.positive": "total_modules_must_be_positive",
                "any.required": "total_modules_required"
            }),

        totalCells: joi.number()
            .integer()
            .positive()
            .required()
            .messages({
                "number.base": "total_cells_must_be_number",
                "number.integer": "total_cells_must_be_integer",
                "number.positive": "total_cells_must_be_positive",
                "any.required": "total_cells_required"
            }),

        cellVoltage: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        cellTemperature: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        cellSoc: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required(),

        cellSoh: joi.object({
            scale: joi.number().required(),
            offset: joi.number().required(),
            type: joi.string()
                .valid("word")
                .required()
        }).required()
    });

    const { error } = schema.validate(req.body);

    if (error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message
        });
    }

    next();
};
//End bms management validate

//Alarm management
const createAlarmValidate = (req, res, next) => {
    const schema = joi.object({
        alarmLevel: joi.string().required()
            .messages({
                "string.empty": "v_createAlarmValidate_alarmLevel_empty",
            }),
        alarmMessage: joi.string().required()
            .messages({
                "string.empty": "v_createAlarmValidate_alarmMessage_empty",
            }),  
        alarmAddress: joi.number().required(),
    });

    const { error } = schema.validate(req.body);

    if(error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message
        })
    };

    next();
}

const editAlarmValidate = (req, res, next) => {
    const schema = joi.object({
        alarmId: joi.number().required(),
        alarmLevel: joi.string().required()
            .messages({
                "string.empty": "v_editAlarmValidate_alarmLevel_empty",
            }),
        alarmMessage: joi.string().required()
            .messages({
                "string.empty": "v_editAlarmValidate_alarmMessage_empty",
            }),  
    });

    const { error } = schema.validate(req.body);

    if(error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message
        })
    };

    next();
}

const deleteAlarmValidate = (req, res, next) => {
    const schema = joi.object({
        id: joi.number().required(),
    });

    const { error } = schema.validate(req.body);

    if(error) {
        return res.status(400).json({
            status: false,
            msg: error.details[0].message
        })
    };

    next();
}
//End alarm management
module.exports = {
    loginValidate,
    renderOtpValidate,
    verifyOtpValidate,
    changePasswordWithOtpValidate,
    changePasswordValidate,
    renderOtpWhenCreateUserValidate,
    createUserValidate,
    updateUserValidate,
    deleteUserValidate,
    recoveryAndDeleteUserRecoveryValidate,
    createRoleValidate,
    deleteRoleValidate,
    updateRoleValidate,
    createRackValidate,
    editRackValidate,
    createModuleValidate,
    editModuleValidate,
    createAlarmValidate,
    editAlarmValidate,
    deleteAlarmValidate,
}