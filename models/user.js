/** User class for message.ly */
const bcrypt = require('bcrypt');
const config = require('../config.js')

const db = require('../db.js');
const ExpressError = require('../expressError.js');


/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */
  static async register({username, password, first_name, last_name, phone}) { 

    try {
      const newDate = new Date();
      const hashedPassword = await bcrypt.hash(password, 1) // 1 instead of BCRYPT_WORK_FACTOR for testing only
      const createQuery = await db.query(`
        INSERT INTO users
        (username, password, first_name, last_name, phone, join_at, last_login_at)
        VALUES($1, $2, $3, $4, $5, $6, $7)
        RETURNING username, 
        password, 
        first_name, 
        last_name, 
        phone
      `, [username, hashedPassword, first_name, last_name, phone, newDate, newDate])

      return { 
        username: createQuery.rows[0].username,
        password: createQuery.rows[0].password,
        first_name: createQuery.rows[0].first_name,
        last_name: createQuery.rows[0].last_name,
        phone: createQuery.rows[0].phone,
      }
    } catch(e) {
      throw(e);
    }

  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    try {
      const findQuery = await db.query(`
        SELECT password FROM users
        WHERE username=$1
      `, [username])
      if (findQuery.rows.length !== 1) {
        return false;
      } else {
        const hashedPassword = findQuery.rows[0].password;
        return bcrypt.compare(password, hashedPassword);

      }
    } catch(e) {
      throw(e);
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) { 
    try {
      const updateQuery = await db.query(`
        UPDATE users 
        SET last_login_at=$1
        WHERE username=$2
      `, [new Date(), username])
    } catch(e){ 
      throw(e);
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
    try {
      const getAllQuery = await db.query(`
        SELECT username, first_name, last_name, phone
        FROM users
      `)
      return getAllQuery.rows;
    } catch(e) {
      throw(e);
    }
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    try {
      const getQuery = await db.query(`
        SELECT username, first_name, last_name, phone, join_at, last_login_at
        FROM users
        WHERE username=$1
      `, [username])
      return getQuery.rows[0]
    } catch(e) {
      throw(e);
    }
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 

    try {
      const messagesFromQuery = await db.query(`
        SELECT msg.id, msg.body, msg.sent_at, msg.read_at, users.username, users.first_name, users.last_name, users.phone
        FROM messages as msg
        LEFT JOIN users
        ON msg.to_username = users.username
        WHERE from_username=$1
      `, [username])

      return messagesFromQuery.rows.map(row => {
        return {
          id: row.id,
          to_user: {
            username: row.username, 
            first_name: row.first_name, 
            last_name: row.last_name, 
            phone: row.phone
          },
          body: row.body,
          sent_at: row.sent_at,
          read_at: row.read_at,
        }
      })
    } catch(e) {
      throw(e)
    }
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 

    try {
      const messagesToQuery = await db.query(`
        SELECT msg.id, msg.body, msg.sent_at, msg.read_at, users.username, users.first_name, users.last_name, users.phone
        FROM messages as msg
        LEFT JOIN users
        ON msg.from_username = users.username
        WHERE to_username=$1
      `, [username])

      return messagesToQuery.rows.map(row => {
        return {
          id: row.id,
          from_user: {
            username: row.username, 
            first_name: row.first_name, 
            last_name: row.last_name, 
            phone: row.phone
          },
          body: row.body,
          sent_at: row.sent_at,
          read_at: row.read_at,
        }
      })
    } catch(e) {
      throw(e)
    }

  }
}





module.exports = User;