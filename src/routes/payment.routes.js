const express = require("express");
const router = express.Router();
const PaymentInfo = require("../models/payment.model");

// Route to handle the creation of a new payment info entry
router.post("/paymentinfo", async (req, res) => {
  try {
    const {
      name,
      college,
      batch,
      fbIdName,
      fbIdLink,
      transactionId,
      courseName,
    } = req.body;

    // Create a new payment info document
    const paymentInfo = new PaymentInfo({
      name,
      college,
      batch,
      fbIdName,
      fbIdLink,
      transactionId,
      courseName,
    });

    // Save the payment info to the database
    await paymentInfo.save();

    res
      .status(201)
      .json({ message: "Payment information saved successfully!" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Route to fetch all payment info entries
router.get("/paymentinfo", async (req, res) => {
  try {
    const paymentInfoEntries = await PaymentInfo.find({});
    res.status(200).json(paymentInfoEntries);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

module.exports = router;
