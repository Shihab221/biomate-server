/* eslint-disable no-console */
import mongoose from "mongoose";
import config from "../src/config/config";
import app from "../src/app";
import cors from "cors";


// const corsOptions = {
//   origin: 'http://www.biomatebd.com', // Allow only specific origin
//   methods: 'GET,POST', // Specify allowed methods
//   allowedHeaders: ['Content-Type', 'Authorization'], // Specify allowed headers
//   credentials: true, // Allow credentials (cookies, etc.)
// };

app.use(cors());

app.listen(config.port, (err) => {
  if (err) console.log(err);
  console.log(`Server started at port ${config.port}`);
});

mongoose.Promise = global.Promise;
mongoose
  .connect(config.mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB successfully connected..."))
  .catch((e) => console.log(e));
