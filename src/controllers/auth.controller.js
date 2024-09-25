/* eslint-disable no-underscore-dangle */
import jwt from "jsonwebtoken";
import expressJwt from "express-jwt";
import User from "../models/user.model";
import config from "../config/config";
import Course from "../models/courses.model";

const signin = async (req, res) => {
  const courseNum = await Course.find({}).exec();

  User.findOne({ email: req.body.email }, (err, user) => {
    if (user && user.active === "inactive") {
      return res.send({ error: "You account has not been activated yet." });
    }
    if (user && user.active === "closed") {
      return res.send({
        error: "You have deleted your account. Please sign up again.",
      });
    }
    if (user && user.active === "deactivated") {
      return res.send({
        error:
          "Your account has been deactivated. Contact admin to reactivate your account",
      });
    }
    if (err || !user) {
      return res.send({ error: "User not found" });
    }
    if (!user.authenticate(req.body.password)) {
      return res.send({ error: "Email and password do not match" });
    }

    const token = jwt.sign(
      {
        _id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
      config.secret
    );
    res.cookie("userJwtToken", token, {
      expire: new Date() + 999,
      httpOnly: true,
    });

    return res.send({
      token,
      user: {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        userImage: user.userImage,
        enrolledInCourses: user.enrolledInCourses,
        completedCourses: user.completedCourses,
      },
      courseNum: user.role !== "student" ? courseNum.length : null,
    });
  });
};

const signout = (req, res) => {
  res.clearCookie("userJwtToken");
  res.send({ message: "User signed out" });
};

const requireSignin = expressJwt({
  secret: config.secret,
  algorithms: ["HS256"],
  userProperty: "auth",
});

const hasAuthorization = (req, res, next) => {
  const authorized = req.profile && req.auth && req.profile._id == req.auth._id;
  if (!authorized) return res.status(403).json("User is not authorized!");
  next();
};

export default {
  signin,
  signout,
  hasAuthorization,
  requireSignin,
};
