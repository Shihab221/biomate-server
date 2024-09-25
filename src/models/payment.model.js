const mongoose = require("mongoose");

const PaymentSchema = new mongoose.Schema({
  name: {
    type: String,
    required: "Name is required!",
  },
  college: {
    type: String,
    required: "College is required!",
  },
  batch: {
    type: String,
    required: "Batch is required!",
  },
  fbIdName: {
    type: String,
    required: "Facebook ID name is required!",
  },
  fbIdLink: {
    type: String,
  },
  transactionId: {
    type: String,
    required: "Transaction ID is required!",
  },

  courseName: {
    type: String,
    required: "Coursename is required",
  },
  coupon: {
    type: String,
  },
  created: {
    type: Date,
    default: Date.now,
  },
});

const Payment = mongoose.model("PaymentInfo", PaymentSchema);
module.exports = Payment;
