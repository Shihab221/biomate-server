// require("dotenv").config();

// const password = process.env.PASSWORD;
// const database = process.env.DATABASE;
// const user = process.env.USER;

// const config = {
//   port: 5000,
//   secret: process.env.JWT_SECRET || "ay+5M9*85&B8W*zp",
//   mongoUri:
//     process.env.MONGO_URI ||
//     `mongodb+srv://${user}:${password}@cluster0.hbhrs.mongodb.net/${database}?retryWrites=true&w=majority`,
// };

// module.exports = config;

require("dotenv").config();

const password = process.env.PASSWORD;
const database = process.env.DATABASE;
const user = process.env.USER;

// Validate essential environment variables
if (!password) {
  throw new Error("Missing required environment variable: PASSWORD");
}
if (!database) {
  throw new Error("Missing required environment variable: DATABASE");
}
if (!user) {
  throw new Error("Missing required environment variable: USER");
}

const config = {
  port: 5000,
  secret: process.env.JWT_SECRET || "ay+5M9*85&B8W*zp",
  mongoUri:
    process.env.MONGO_URI ||
    `mongodb+srv://Shihab22:%40Greenlif22@cluster0.2uxncrv.mongodb.net/todos`,
};

module.exports = config;
