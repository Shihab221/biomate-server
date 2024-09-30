import passport from "passport";
import passportJwt from "passport-jwt";
import config from "../config/config";

// const cookieExtractor = (req) => {
//   let jwt;

//   if (req && req.cookies) {
//     jwt = req.cookies;
//   }

//   return jwt.userJwtToken;
// };

//gpt code
const cookieExtractor = (req) => {
  let jwt = null;
  if (req && req.cookies && req.cookies.userJwtToken) {
    jwt = req.cookies.userJwtToken;
  }
  return jwt;
};

const JWTStrategy = passportJwt.Strategy;

passport.use(
  new JWTStrategy(
    {
      jwtFromRequest: cookieExtractor,
      secretOrKey: config.secret,
    },
    (jwtPayload, done) => {
      if (jwtPayload) {
        return done(null, jwtPayload);
      }
      return done(null, false);
    }
  )
);
