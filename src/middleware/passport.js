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

export const tokenExtractor = (req) => {
  let token = null;

  // Check if the Authorization header exists
  if (req && req.headers && req.headers.authorization) {
    const authHeader = req.headers.authorization;

    // Check if the Authorization header contains a Bearer token
    if (authHeader.startsWith("Bearer ")) {
      // Extract the token from the "Bearer <token>" string
      token = authHeader.split(" ")[1]; // Extracts the token after "Bearer"
    }
  }

  return token;
};

//gpt code
// const cookieExtractor = (req) => {
//   let jwt = null;
//   if (req && req.cookies && req.cookies.userJwtToken) {
//     jwt = req.cookies.userJwtToken;
//   }
//   return jwt;
// };

const JWTStrategy = passportJwt.Strategy;

passport.use(
  new JWTStrategy(
    {
      jwtFromRequest: tokenExtractor, //edited here
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
