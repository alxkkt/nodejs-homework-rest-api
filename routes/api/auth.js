const express = require("express");
const bcrypt = require("bcryptjs");
const Joi = require("joi");

const User = require("../../models/user");
const { createError } = require("../../helpers");

const router = express.Router();

const emailRegexp = /[a-z0-9]+@[a-z]+\.[a-z]{2,3}/;

const userRegisterSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().pattern(emailRegexp).required(),
  password: Joi.string().min(6).required(),
});

const userLoginSchema = Joi.object({
  email: Joi.string().pattern(emailRegexp).required(),
  password: Joi.string().min(6).required(),
});

// signup
router.post("/register", async (req, res, next) => {
  try {
    const { error } = userRegisterSchema.validate(req.body);

    if (error) {
      throw createError(400, error.message);
    }

    const { email, password, name } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      throw createError(409, "Email already registered");
    }

    const hashPassword = await bcrypt.hash(password, 10);
    const result = await User.create({ email, password: hashPassword, name });
    res.status(201).json({
      name: result.name,
      email: result.email,
    });
  } catch (error) {
    next(error);
  }
});

// signin
router.post("/login", async (req, res, next) => {
  try {
    const { error } = userLoginSchema.validate(req.body);
    if (error) {
      throw createError(400, error.message);
    }

    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      throw createError(401, "Email wrong");
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      throw createError(401, "Password wrong");
    }
    // if (!user || !isValidPassword) {
    //   throw createError(401, "Email or password is wrong")
    // }

    const token = "OLOLO";
    res.json({
      token,
    });
  } catch (error) {
    next(error);
  }
});
module.exports = router;
