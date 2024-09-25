/* eslint-disable no-underscore-dangle */
const mongoose = require("mongoose");
const _ = require("lodash");
const Courses = require("./src/models/courses.model");
const Users = require("./src/models/user.model");
const config = require("./src/config/config");

const courses = [];
const usersId = [];
const enrolledStudents = [];

const users = [
  {
    firstName: "Mak",
    lastName: "Ovcina",
    email: "mak.ovcina@test.com",
    password: "12345678",
    role: "mentor",
  },
  {
    firstName: "John",
    lastName: "Doe",
    email: "john.doe@test.com",
    password: "12345678",
    role: "student",
  },
  {
    firstName: "John",
    lastName: "Smith",
    email: "hugo_tutto_cammara@test.com",
    password: "12345678",
    role: "mentor",
  },
  {
    firstName: "Larry",
    lastName: "Bird",
    email: "harry.lattam@test.com",
    password: "12345678",
    role: "student",
  },
  {
    firstName: "paragon",
    lastName: "paragon",
    email: "paragon@paragon.ba",
    password: "Paragon202!",
    role: "admin",
    active: true,
  },

  {
    firstName: "Luka",
    lastName: "Ovcina",
    email: "luka.ovcina@test.com",
    password: "12345678",
    role: "mentor",
  },
  {
    firstName: "Marina",
    lastName: "Ovcina",
    email: "marina.ovcina@test.com",
    password: "12345678",
    role: "mentor",
  },
  {
    firstName: "Adnan",
    lastName: "Ovcina",
    email: "adnan.ovcina@test.com",
    password: "12345678",
    role: "mentor",
  },
];

const levels = ["Beginner Level", "Intermediate Level", "Advanced Level"];
const duration = [
  "0 - 3 Hours",
  "3 - 6 Hours",
  "6 - 12 Hours",
  "1 - 2 Days",
  "2 - 5 Days",
  "5 - 15 Days",
];

const coursesTitlesAndImages = [
  {
    title: `Node.js - Beginner course`,
    image:
      "https://buddy.works/guides/covers/test-nodejs-app/share-nodejs-logo.png",
  },
  {
    title: `React.js - Beginner course`,
    image: "https://blog.wildix.com/wp-content/uploads/2020/06/react-logo.jpg",
  },
  {
    title: `Vue.js - Beginner course`,
    image: "https://miro.medium.com/max/900/0*EBTwokY-nMyAvDAQ",
  },
  {
    title: `Angular.js - Beginner course`,
    image:
      "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSY5G3jvh6ezlW2kdJWWuWs1vELTstyFy6RcQ&usqp=CAU",
  },
  {
    title: `Express.js - Beginner course`,
    image:
      "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSY5G3jvh6ezlW2kdJWWuWs1vELTstyFy6RcQ&usqp=CAU",
  },
];

mongoose
  .connect(config.mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB successfully connected..."))
  .catch((e) => console.log(e));

const createUsers = async () => {
  await Users.insertMany(users);
  const user = await Users.where({ role: "mentor" }).exec();

  for (let i = 0; i < 101; i++) {
    const randomIndex = Math.floor(Math.random() * 5);
    courses.push({
      mentorId: user[Math.floor(Math.random() * user.length)]._id,
      title: `${coursesTitlesAndImages[randomIndex].title} - ${i}`,
      level: levels[Math.floor(Math.random() * levels.length)],
      courseImage: coursesTitlesAndImages[randomIndex].image,
      duration: duration[Math.floor(Math.random() * duration.length)],
      description:
        "Sed gravida velit vitae condimentum posuere. Donec libero mauris, tempor ac luctus ut.",
      status: "active",
    });
  }
  await Courses.insertMany(courses);
};

createUsers()
  .then(() => {
    mongoose.connection.close();
  })
  .catch((err) => console.log(err));
