const User = require("./user");
const User_password_reset = require("./user.password_reset");

user.hasMany(user_password_reset, {foreignKey:"user_id"});
user_password_reset.belongsTo(user, {foreignKey:"user_id"});

module.exports = {
    User,
    User_password_reset
};

