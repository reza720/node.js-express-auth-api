const env = require("./env.config");
const database = require("./database.config");
const jwtConfig = require("./jwt.config");
const logger = require("./logger.config");
const mail = require("./mail.config");
const rateLimiter = require("./rateLimiter.config");

module.exports ={
    env,
    database,
    jwtConfig,
    logger,
    mail,
    rateLimit
};

