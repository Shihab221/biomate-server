import express from "express";
import passport from "passport";
import adminCtrl from "../controllers/admin.controller";

require("../middleware/passport");

const router = express.Router();

router.get(
  "/protected",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    if (req.cookies.userJwtToken) {
      res.send(JSON.stringify({ message: req.cookies.userJwtToken }));
    }
  }
);

router
  .route("/admin/courses")
  .post(adminCtrl.getAllUsers, adminCtrl.getCourses);

router.route("/admin/users").post(adminCtrl.getUsers);
router.route("/admin/createUser").post(adminCtrl.createUser);
router.route("/admin/course/:courseId").post(adminCtrl.removeCourse);
router.route("/admin/users/:userId").put(adminCtrl.activateUserAccount);
router.param("courseId", adminCtrl.courseByID);
router.param("userId", adminCtrl.userByID);

export default router;
