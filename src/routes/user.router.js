const {
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
} = require("../controllers/user.controller");
const express = require("express");
const verifyJWT = require("../utils/verifyJWT");

const userRouter = express.Router();

userRouter.route("/").get(verifyJWT, getAll).post(create);

userRouter.route("/verify/:code").get(verifyUser);

userRouter.route("/reset_password").post(recoveyPassword)

userRouter.route("/reset_password/:code").post(resetPassword)

userRouter.route("/login").post(login);

userRouter.route("/me").get(verifyJWT, getLoggedUser)

userRouter.route("/:id").get(verifyJWT, getOne).delete(verifyJWT, remove).put(verifyJWT, update);

module.exports = userRouter;
