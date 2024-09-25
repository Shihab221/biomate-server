import express from "express";
import compress from "compression";
import cors from "cors";
import helmet from "helmet";
import passport from "passport";
import cookieParser from "cookie-parser";
import userRoutes from "./routes/user.routes";
import authRoutes from "./routes/auth.routes";
import userImageRoutes from "./routes/userImage.routes";
import courseRoutes from "./routes/course.routes";
import adminRoutes from "./routes/admin.routes";
const paymentInfoRoutes = require("./routes/payment.routes");
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(compress());
app.use(cors());
app.use(helmet());
app.use(passport.initialize());
app.use(cookieParser());

app.use("/", authRoutes);
app.use("/", userRoutes);

app.use("/", courseRoutes);
app.use("/", adminRoutes);

app.use("/images", express.static("images"));
app.use("/", userImageRoutes);
app.use("/api", paymentInfoRoutes);

app.use((err, req, res, next) => {
  if (err.name === "UnauthorizedError") {
    res.status(401).json({ error: `${err.name} : ${err.message}` });
  }
});

export default app;
