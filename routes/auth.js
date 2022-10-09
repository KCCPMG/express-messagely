const router = require('express').Router();
const ExpressError = require('../expressError.js');
const User = require('../models/user.js');
const jwt = require('jsonwebtoken');



/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post('/login', async (req, res, next) => {
  try {
    const boolAuthenticated = await User.authenticate(req.body.username, req.body.password)
    if (boolAuthenticated) {
      await User.updateLoginTimestamp(req.body.username);

      const token = jwt.sign({
        username: req.body.username, 
        iat: Date.parse(new Date().toISOString())
      }, process.env.SECRET_KEY); 

      return res.json({
        token 
      });

    } else {
      return res.status(400).send("Invalid Credentials");
    }

  } catch(e) {
    return next(e);
  }
})

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post('/register', async (req, res, next) => {
  try {

    await User.register(req.body);

    const token = jwt.sign({
      username: req.body.username, 
      iat: Date.parse(new Date().toISOString())
    }, process.env.SECRET_KEY); 

    res.json({token})

  } catch(e) {
    throw(e);
  }
})


module.exports = router;