const router = require("express").Router();
const Users = require("./users-model.js");
const { restricted, only } = require("../auth/auth-middleware.js");

router.get("/", restricted, (req, res, next) => { // done for you
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(next);
});

router.get("/:user_id", restricted, only('admin'), (req, res, next) => { // done for you
  Users.findById(req.params.user_id)
    .then(user => {
      res.json(user);
    })
    .catch(next);
});

module.exports = router;
