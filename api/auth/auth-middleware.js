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
}

const validateRoleName = (req, res, next) => {
  const {role_name} = req.body;
  if(!role_name || !role_name.trim()) {
    req.body.role_name = 'student';
    next();
  } else if(role_name.trim() === 'admin') {
    next({status: 422, message: 'Role name can not be admin'});
  } else if(role_name.trim().length > 32) {
    next({status: 422, message: 'Role name can not be longer than 32 chars'});
  } else {
    req.body.role_name = role_name.trim();
    next();
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
