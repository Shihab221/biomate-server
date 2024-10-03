/* eslint-disable no-underscore-dangle */
import jwt from "jsonwebtoken";
import expressJwt from "express-jwt";
import User from "../models/user.model";
import config from "../config/config";
import Course from "../models/courses.model";

// Asynchronous signin with better error handling
const signin = async (req, res) => {
  try {
    // Fetching all courses (only needed if the user is not a student)
    const courseNum = await Course.find({}).exec();

    const user = await User.findOne({ email: req.body.email }).exec();
    if (!user) {
      return res.send({ error: "User not found" });
    }

    if (user.active === "inactive") {
      return res.send({ error: "Your account has not been activated yet." });
    }
    if (user.active === "closed") {
      return res.send({
        error: "You have deleted your account. Please sign up again.",
      });
    }
    if (user.active === "deactivated") {
      return res.send({
        error: "Your account has been deactivated. Contact admin to reactivate your account.",
      });
    }

    // Check if the password is valid
    if (!user.authenticate(req.body.password)) {
      return res.send({ error: "Email and password do not match" });
    }

    // Sign JWT token with a limited expiration time (e.g., 1 day)
    const token = jwt.sign(
      {
        _id: user._id,
        role: user.role,
      },
      config.secret,
      { expiresIn: "1d" } // Token expires in 1 day
    );

    // Securely set the JWT token as a cookie
    res.cookie("userJwtToken", token, {
      expire: new Date() + 999,
      httpOnly: true,
      // Uncomment these lines when running in production with HTTPS
      // secure: true, // for HTTPS
      // sameSite: "Strict", // Prevent CSRF attacks
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
  } catch (error) {
    console.error("Error in signin:", error);
    return res.status(500).send({ error: "Internal server error" });
  }
};

const signout = (req, res) => {
  res.clearCookie("userJwtToken");
  res.send({ message: "User signed out" });
};

// Middleware to require authentication
const requireSignin = expressJwt({
  secret: config.secret,
  algorithms: ["HS256"],
  userProperty: "auth",
});

// Middleware to check if the user is authorized
const hasAuthorization = (req, res, next) => {
  const authorized = req.profile && req.auth && req.profile._id == req.auth._id;
  if (!authorized) return res.status(403).json({ error: "User is not authorized!" });
  next();
};

export default {
  signin,
  signout,
  hasAuthorization,
  requireSignin,
};
