const Message = require('../models/message');
const {ensureLoggedIn} = require('../middleware/auth')
const router = require('express').Router();

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/
router.get('/:id', ensureLoggedIn, async (req, res, next) => {
  try {
    const message = await Message.get(req.params.id);
    if (req.user.username === message.to_user.username || req.user.username === message.from_user.username) {
      return res.json(message);
    } else {
      res.json({message: "Not authorized"})
    }

  } catch(e) {
    next(e);
  }
})

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
 router.post('/', ensureLoggedIn, async (req, res, next) => {
  try {
    const message = await Message.create(req.body);
    return res.json({message});
  } catch(e) {
    next(e);
  }
})

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/
 router.post('/:id', ensureLoggedIn, async (req, res, next) => {
  try {
    const message = await Message.get(req.params.id);
    if (message.to_user.username === req.user.username) {
      const readMessage = await Message.markRead(req.params.id);
      return res.json({readMessage});
    } else {
      res.json({message: "Not authorized"})
    }
  } catch(e) {
    next(e);
  }
})


module.exports = router;