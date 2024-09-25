const mongoose = require("mongoose");

const CoursesSchema = new mongoose.Schema({
  title: {
    type: String,
    trim: true,
    unique: "Title must be unique",
    required: "Course title is required!",
    maxlength: [55, "Title must be less than 55 characters"],
  },
  description: {
    type: String,
    required: "Course description is required!",
  },
  level: {
    type: String,
    required: "Course level is required!",
  },
  duration: {
    type: String,
    required: "Course duration is required!",
  },
  courseImage: {
    type: String,
  },
  created: {
    type: Date,
    default: Date.now,
  },
  mentorId: {
    type: String,
    required: "Course must have an mentor",
  },
  status: {
    type: String,
    default: "active",
  },
  enrolledStudents: {
    type: Array,
  },
  fee: {
    type: Number,
  },
  updated: Date,
});

CoursesSchema.path("title").validate(async function (title) {
  const course = await this.constructor.findOne({ title });
  if (course) {
    if (this.id === course.id) {
      return true;
    }
    return false;
  }
  return true;
}, "Course title must be unique!");

const Course = mongoose.model("Courses", CoursesSchema);
module.exports = Course;
