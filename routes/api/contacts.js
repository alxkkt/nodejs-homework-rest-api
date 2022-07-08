const express = require("express");
const Joi = require("joi");

const router = express.Router();

const contacts = require("../../models/contacts");
const { createError } = require("../../helpers");

const contactScheme = Joi.object({
  name: Joi.string().required(),
  phone: Joi.string().required(),
  email: Joi.string().required(),
});

router.get("/", async (req, res, next) => {
  try {
    const result = await contacts.listContacts();
    res.json(result);
  } catch (error) {
    next(error);
  }
});

router.get("/:contactId", async (req, res, next) => {
  try {
    const { contactId } = req.params;
    console.log(contactId);
    const result = await contacts.getContactById(contactId);
    if (!result) {
      throw createError(404, "Not Found");
      // res.status(404).json({
      //   message: "Not found",
      // });
      // return;
    }
    res.json(result);
  } catch (error) {
    next(error);
  }
});

router.post("/", async (req, res, next) => {
  try {
    const { error } = contactScheme.validate(req.body);

    if (error) {
      throw createError(400, error.message);
    }

    const result = await contacts.addContact(req.body);
    res.status(201).json(result);
  } catch (error) {
    next(error);
  }
});

router.delete("/:contactId", async (req, res, next) => {
  try {
    const { contactId } = req.params;
    const result = await contacts.removeContact(contactId);
    if (!result) {
      throw createError(404, "Not Found");
    }
    res.json({ message: "Contact Deleted" });
  } catch (error) {
    next(error);
  }
});

router.put("/:contactId", async (req, res, next) => {
  try {
    const { error } = contactScheme.validate(req.body);
    if (error) {
      throw createError(400, error.message);
    }

    const { contactId } = req.params;
    const result = await contacts.updateContact(contactId, req.body);
    if (!result) {
      throw createError(404, "Not Found");
    }

    res.json(result);
  } catch (error) {
    next(error);
  }
});

module.exports = router;
