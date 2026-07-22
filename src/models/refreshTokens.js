const {database} = require("../config");
const {DataTypes} = require("sequelize");

const RefreshToken = database.define("RefreshToken",{
    id:{
        type:DataTypes.INTEGER,
        primaryKey:true,
        autoIncrement:true
    },
    userId:{
        type:DataTypes.INTEGER,
        allowNull:false
    },
    tokenHash:{
        type:DataTypes.STRING,
        allowNull:false,
        unique:true
    },
    expiresAt:{
        type:DataTypes.DATE,
        allowNull:false
    },
    revokedAt:{
        type:DataTypes.DATE,
        allowNull:true
    }
},{
    timestamps:true
});

module.exports=RefreshToken;