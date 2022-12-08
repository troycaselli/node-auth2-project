const jwt = require('jsonwebtoken');

const { JWT_SECRET } = require("../secrets");
const Users = require('../users/users-model');

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if(token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if(err) {
        next({status: 401, message: 'Token invalid'});
      } else {
        req.decodedJwt = decoded;
        console.log(decoded);
        next();
      }
    })
  } else {
    next({status: 401, message: 'Token required'});
  }
}

const only = role_name => (req, res, next) => {
  if(req.decodedJwt.role_name !== role_name) {
    next({status: 403, message: 'This is not for you'});
  } else {
    next();
  }
}


const checkUsernameExists = async (req, res, next) => {
  try {
    const {username} = req.body;
    const users = await Users.findBy({username});
    if(users.length) {
      req.user = users[0];
      next();
    } else {
      next({status: 401, message: 'Invalid credentials'});
    }

  } catch (err) {
    next(err);
  }

  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
}


const validateRoleName = (req, res, next) => {
  next()
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
