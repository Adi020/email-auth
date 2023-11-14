const catchError = require("../utils/catchError");
const User = require("../models/User");
const bcrypt = require("bcrypt");
const sendEmail = require("../utils/sendEmail");
const EmailCode = require("../models/EmailCode");
const jwt = require("jsonwebtoken");

const getAll = catchError(async (req, res) => {
  const results = await User.findAll();
  return res.json(results);
});

const create = catchError(async (req, res) => {
  const { email, password, firstName, lastName, image, country, frontBaseUrl } =
    req.body;
  const encriptedPassword = await bcrypt.hash(password, 10);
  const result = await User.create({
    email,
    password: encriptedPassword,
    firstName,
    lastName,
    image,
    country,
  });
  const code = require("crypto").randomBytes(32).toString("hex");
  const link = `${frontBaseUrl}/auth/verify_email/${code}`;
  await EmailCode.create({ code, userId: result.id });
  await sendEmail({
    to: `${email}`,
    subject: "Verificate email for user app",
    html: `<h1>Hello ${firstName}</h1>
           <p>thanks for sign up in user app</p>
           <br>
           <a href="${link}">${link}</a>`,
  });
  return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.findByPk(id);
  if (!result) return res.sendStatus(404);
  return res.json(result);
});

const remove = catchError(async (req, res) => {
  const { id } = req.params;
  await User.destroy({ where: { id } });
  return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
  const { id } = req.params;
  const { firstName, lastName, country, image } = req.body;
  const result = await User.update(
    { firstName, lastName, country, image },
    {
      where: { id },
      returning: true,
    }
  );
  if (result[0] === 0) return res.sendStatus(404);
  return res.json(result[1][0]);
});

const verifyUser = catchError(async (req, res) => {
  const { code } = req.params;
  const emailCode = await EmailCode.findOne({ where: { code } });
  if (!emailCode) {
    return res.status(401).json({ message: "Code not found" });
  }
  const user = await User.findByPk(emailCode.userId);
  await user.update({ isVerified: true });
  await user.save();
  await emailCode.destroy();
  return res.json(user);
});

const login = catchError(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) {
    return res.status(401).json({ message: "Credentials Invalid" });
  }
  const passwordCompare = await bcrypt.compare(password, user.password);
  if (!passwordCompare) {
    return res.status(401).json({ message: "Credentials Invalid" });
  }
  if (!user.isVerified) {
    return res.status(401).json({ message: "User not verified" });
  }
  const token = jwt.sign({ user }, process.env.TOKEN_SECRET, {
    expiresIn: "1d",
  });
  return res.json({ user, token });
});

const getLoggedUser = catchError(async (req, res) => {
  const user = req.user;
  return res.json(user);
});

const recoveyPassword = catchError(async (req, res) => {
  const { email, frontBaseUrl } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) {
    return res.status(401).json({ message: "User not found" });
  }
  const code = require("crypto").randomBytes(32).toString("hex");
  const link = `${frontBaseUrl}/auth/reset_password/${code}`;
  await EmailCode.create({ code, userId: user.id });
  await sendEmail({
    to: `${email}`, // Email del receptor
    subject: "Reset password for users app", // asunto
    html: `<h1>Hello ${user.firstName}</h1>
           <p>Click below to create a new password</p>
           <br>
           <a href="${link}">${link}</a>`, // texto
  });
  return res.status(201).json({ message: "email send" });
});

const resetPassword = catchError(async (req, res) => {
  const { code } = req.params;
  const emailCode = await EmailCode.findOne({ where: { code } });
  if (!emailCode) {
    return res.status(401).json({ message: "Code not found" });
  }
  const { password } = req.body;
  const encriptedPassword = await bcrypt.hash(password, 10);
  const user = await User.findByPk(emailCode.userId);
  await user.update({ password: encriptedPassword });
  await user.save();
  await emailCode.destroy();
  return res.json(user);
});

module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  verifyUser,
  login,
  getLoggedUser,
  recoveyPassword,
  resetPassword,
};
