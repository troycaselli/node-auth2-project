const router = require("express").Router();
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const Users = require('../users/users-model');
const { JWT_SECRET, BCRYPT_ROUNDS } = require("../secrets");

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    const {username, password, role_name} = req.body;
    const hash = bcryptjs.hashSync(password, BCRYPT_ROUNDS);
    const user = await Users.add({username, password: hash, role_name});
    res.status(201).json(user);
  } catch (err) {
    next(err);
  }

  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    const {username, password} = req.body;
    const users = await Users.findBy({username});
    if(users.length && bcryptjs.compareSync(password, users[0].password)) {
      const token = generateToken(users[0]);
      res.status(200).json({message: `${username} is back!`, token});
    } else {
      res.status(401).json({message: 'Invalid credentials'});
    }
  } catch (err) {
    next(err);
  }

  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

function generateToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const options = {
    expiresIn: '1d'
  }

  return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = router;
