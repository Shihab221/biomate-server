import express from "express";
import passport from "passport";
import userCtrl from "../controllers/user.controller";

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

router.route("/api/users/").post(userCtrl.create);
router.route("/api/userCourses").post(userCtrl.getUserCourses);
router.route("/api/completedCourses").post(userCtrl.courseCompleted);
router
  .route("/api/users/updateUserPassword/:userId")
  .put(userCtrl.updateUserPassword);

router
  .route("/api/users/:userId")
  .get(userCtrl.read)
  .post(userCtrl.enrollInCourse)
  .put(userCtrl.update)
  .delete(userCtrl.remove);

router.route("/api/users/relogin/:userId").get(userCtrl.reLoginUser);

router.route("/api/mentors").get(userCtrl.getAllMentors);

router
  .route("/api/mentorCourses")
  .get(userCtrl.getAllMentors)
  .post(userCtrl.getMentorCourses);

router.param("userId", userCtrl.userByID);

export default router;
