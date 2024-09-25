import _ from "lodash";
import jwtDecode from "jwt-decode";
import Course from "../models/courses.model";
import dbErrorHandlers from "./helpers/dbErrorHandlers";

const createCourse = (req, res) => {
  const course = new Course(req.body);
  course.save((err) => {
    if (err) {
      return res
        .status(400)
        .send({ error: dbErrorHandlers.getErrorMessage(err) });
    }
    return res.status(200).send({ message: "Course successfully created" });
  });
};

const getCourses = (req, res) => {
  // get id to enable filtering of data
  const user = jwtDecode(req.cookies.userJwtToken);

  // filter data - get transactions for last three days
  Course.find({})
    .where("userId")
    .equals(user.id)
    // sort data in descending order
    .sort({ created: -1 })
    .exec((err, transactions) => {
      if (err) {
        return res
          .status(400)
          .send({ error: dbErrorHandlers.getErrorMessage(err) });
      }
      res.status(200).send({ transactions });
    });
};

const getCourse = (req, res) => {
  res.status(200).json(req.course);
};

const updateCourse = (req, res, next) => {
  let course = req.course;
  course = _.extend(course, req.body);
  course.updated = Date.now();
  course.save((err) => {
    if (err) {
      return res
        .status(400)
        .send({ error: dbErrorHandlers.getErrorMessage(err) });
    }
    return res.status(200).send({ message: "Data updated" });
  });
};

const removeCourse = (req, res, next) => {
  const course = req.course;
  course.remove((err) => {
    if (err) {
      return res
        .status(400)
        .send({ error: dbErrorHandlers.getErrorMessage(err) });
    }
    res.status(200).send({ message: "Course deleted" });
  });
};

const getAllCourses = (req, res) => {
  Course.find({}).exec((err, courses) => {
    if (err) {
      res.status(400).send({ error: dbErrorHandlers.getErrorMessage(err) });
    } else {
      res.status(200).send({ courses: courses });
    }
  });
};

const courseByID = (req, res, next, id) => {
  Course.findById(id).exec((err, course) => {
    if (err || !course) {
      return res
        .status(400)
        .send({ error: dbErrorHandlers.getErrorMessage(err) });
    }
    req.course = course;
    next();
  });
};

export default {
  createCourse,
  getCourses,
  updateCourse,
  removeCourse,
  getCourse,
  courseByID,
  getAllCourses,
};
