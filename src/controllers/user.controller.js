/* eslint-disable no-underscore-dangle */
import jwt from "jsonwebtoken";
import _ from "lodash";
import User from "../models/user.model";
import errorHandler from "./helpers/dbErrorHandlers";
import Course from "../models/courses.model";
import config from "../config/config";

const create = (req, res, next) => {
  const user = new User(req.body);
  user.save((err, result) => {
    if (err) {
      res.send({ error: errorHandler.getErrorMessage(err) });
    } else {
      res.send({ message: "Successfuly created a new user." });
    }
  });
};

const reLoginUser = async (req, res) => {
  const courseNum = await Course.find({}).exec();
  User.findOne({ _id: req.profile.id }, (err, user) => {
    const token = jwt.sign(
      {
        _id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
      config.secret
    );

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
      relogin: true,
    });
  });
};

const read = (req, res) => {
  User.findOne({ _id: req.profile.id }, (err, user) => {
    const token = jwt.sign(
      {
        _id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
      config.secret
    );

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
      message: "User found!",
    });
  });
};

const update = async (req, res, next) => {
  let user = req.profile;
  user = _.extend(user, req.body);

  await User.findOneAndUpdate({ _id: req.profile._id }, { ...user }).exec();

  return res.send({
    message: "Data updated",
    data: user,
    token: req.cookies.userJwtToken,
  });
};

const remove = async (req, res, next) => {
  const userProfile = await User.findOne({ _id: req.profile._id });

  if (!userProfile.authenticate(req.body.password)) {
    return res.send({ error: "Incorrect old password" });
  }

  const user = req.profile;
  await User.findOneAndUpdate({ _id: req.profile._id }, { active: "closed" });

  return res.send({ message: "Account deleted" });
};

const updateUserPassword = async (req, res, next) => {
  let user = req.profile;

  user = _.extend(user, req.body);

  const userProfile = await User.findOne({ _id: req.profile._id });

  if (!userProfile.authenticate(req.body.password)) {
    return res.send({ error: "Incorrect old password" });
  }
  user.hashed_password = null;
  user.password = req.body.newPassword;

  user.updated = Date.now();
  user.save((err) => {
    if (err) {
      return res.send({ error: errorHandler.getErrorMessage(err) });
    }
    return res.send({
      message: "Data updated",
      data: user,
    });
  });
};

const enrollInCourse = async (req, res) => {
  const user = await User.findByIdAndUpdate(
    { _id: req.body.id },
    { $push: { enrolledInCourses: req.body.courseId } }
  );
  if (user) {
    res.send({ message: "User enrolled" });
  } else {
    res.send({ error: errorHandler.getErrorMessage(err) });
  }
};

const courseCompleted = async (req, res) => {
  const user = await User.findByIdAndUpdate(
    { _id: req.body.id },
    { $push: { completedCourses: req.body.courseId } }
  );
  if (user) {
    res.send({ message: "Course completed" });
  } else {
    res.send({ error: errorHandler.getErrorMessage(err) });
  }
};

const getUserCourses = (req, res) => {
  Course.find({}, (err, course) => {
    const userCourses = [];

    if (err) {
      return res.send({ error: errorHandler.getErrorMessage(err) });
    }
    course.map((item, index) => {
      if (req.body.completedCourses.length !== 0) {
        if (
          req.body.userCourses.includes(item._id.toString()) &&
          !req.body.completedCourses.includes(item._id)
        ) {
          userCourses.push(item);
        }
      } else {
        if (req.body.userCourses.includes(item._id.toString())) {
          userCourses.push(item);
        }
      }
    });

    return res.send({
      data: req.body.filterTerm
        ? userCourses.filter((course) =>
            course.title
              .toLowerCase()
              .includes(req.body.filterTerm.toLowerCase())
          )
        : userCourses,
    });
  });
};

const getMentorCourses = (req, res) => {
  Course.find({ mentorId: req.body.mentorId })
    .where({ status: "active" })
    .exec((err, course) => {
      if (err) {
        return res.send({ error: errorHandler.getErrorMessage(err) });
      }
      return res.send({
        data: req.body.filterTerm
          ? course
              .filter((item) => item.title.includes(req.body.filterTerm))
              .slice(req.body.firstItem, req.body.lastItem)
          : course.slice(req.body.firstItem, req.body.lastItem),

        totalNumOfCourses: req.body.filterTerm
          ? course.filter((item) => item.title.includes(req.body.filterTerm))
              .length
          : course.length,
      });
    });
};
const getAllMentors = (req, res) => {
  User.find({}).exec((err, user) => {
    if (err) {
      res.send({ err: "error" });
    } else {
      res.send({ mentors: user });
    }
  });
};

const userByID = (req, res, next, id) => {
  User.findById(id).exec((err, user) => {
    if (err || !user) {
      return res.json({ error: "User not found!" });
    }
    req.profile = user;
    next();
  });
};

export default {
  create,
  read,
  update,
  remove,
  updateUserPassword,
  enrollInCourse,
  courseCompleted,
  getUserCourses,
  getAllMentors,
  getMentorCourses,
  reLoginUser,
  userByID,
};
