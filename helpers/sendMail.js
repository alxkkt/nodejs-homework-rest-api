const sgMail = require("@sendgrid/mail");
require("dotenv").config();

const { SENDGRID_API_KEY } = process.env;
sgMail.setApiKey(SENDGRID_API_KEY);

/*
const mail = {
    to: "userEmail@mail.com",
    from: "myEmail@mail.com",
    subject: "insert your subject",
    html: "<p>Insert mail message</p>"
}
 */

const sendMail = async (data) => {
  const mail = { ...data, from: "kikot.oleksii@gmail.com" }; // from registered email on app.sendgrid

  try {
    await sgMail.send(mail);

    return true;
  } catch (error) {
    console.log(error); // to avoid eslint warning underline
    throw error;
  }
};

module.exports = sendMail;
