const mongoose = require("mongoose");
const crypto = require("crypto");
const validate = require("mongoose-validator");

const emailValidator = [
  validate({
    validator: "isEmail",
    message: "Please enter valid email address ",
  }),
];

const UserSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: "First name is required",
    trim: true,
    maxlength: [30, "First name must be less than 15 characters"],
    match: [
      /^[a-zA-Z0-9\s]+$/,
      "Special characters are not allowed in first name",
    ],
  },
  lastName: {
    type: String,
    required: "Last name is required",
    trim: true,
    maxlength: [30, "Last name must be less than 20 characters"],
    match: [
      /^[a-zA-Z0-9\s]+$/,
      "Special characters are not allowed in last name",
    ],
  },
  email: {
    type: String,
    unique: "Email already exists.",
    validate: emailValidator,

    required: "Email is required",
  },
  created: {
    type: Date,
    default: Date.now,
  },
  userImage: {
    type: String,
    default: "",
  },
  updated: Date,
  hashed_password: {
    type: String,
    required: "Password is required",
  },
  numberOfCompletedCourses: {
    type: Number,
    default: 0,
  },
  role: {
    type: String,
  },
  active: {
    type: String,
    default: "inactive",
  },
  enrolledInCourses: {
    type: Array,
  },
  completedCourses: {
    type: Array,
  },
  salt: String,
});

UserSchema.virtual("password").set(function (password) {
  (this._password = password),
    (this.salt = this.makeSalt()),
    (this.hashed_password = this.encryptPassword(password));
});

UserSchema.methods = {
  authenticate(plainText) {
    return this.encryptPassword(plainText) === this.hashed_password;
  },
  encryptPassword(password) {
    if (!password) return "";
    try {
      return crypto
        .createHmac("sha1", this.salt)
        .update(password)
        .digest("hex");
    } catch (err) {
      return err;
    }
  },
  makeSalt() {
    return `${Math.round(new Date().valueOf() * Math.random())}`;
  },
};

UserSchema.path("hashed_password").validate(function (v) {
  if (this._password && this._password.length < 8) {
    this.invalidate("password", "Password must be at least 8 characters");
  }
}, null);

UserSchema.path("email").validate(async function (email) {
  const user = await this.constructor.findOne({ email });
  if (user) {
    if (this.id === user.id) {
      return true;
    }
    return false;
  }
  return true;
}, "Email already exists!");

const User = mongoose.model("User", UserSchema);
module.exports = User;
