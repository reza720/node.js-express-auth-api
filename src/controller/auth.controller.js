const { database } = require("../config/env.config");
const authService= require("../services/auth.service");


// Signup controller
async function signup(req, res, next) {
    try{
        const user = await authService.signup(req.body);
        res.status(201).json({
            success: true, 
            message: "user signed up", 
            user
        });
    }
    catch(err){
        next(err);
    }
};

// Email verification request
async function requestEmailVerification(req, res, next) {
    try{
        await authService.requestEmailVerification(req.user.id);
        res.status(200).json({
            success:true,
            message: "Verification email sent"
        });
    }
    catch(err){
        next(err);
    }
};

// Verify Email
async function requestEmailVerification(req, res, next) {
    try{
        const {token} = req.query;
        const user = await authService.requestEmailVerification(token);
        res.status(200).json({
            success:true,
            message: "Email verified",
            user
        });
    }
    catch(err){
        next(err);
    }
};

// Login
async function login(req, res, next) {
    try{
        const user = await authService.login(req.body);
        res.status(200).json({
            success: true, 
            message: "user logged in",
            user
        });
    }
    catch(err){
        next(err);
    }
};

// Refresh Access Token
async function refreshAccessToken(req, res, next) {
    try{
        const accessToken = await authService.refreshAccessToken(req.body.refreshToken);
        res.status(200).json({
            success:true,
            message: "Access token generated",
            ...accessToken
        });
    }
    catch(err){
        next(err);
    }
};

// Update Password
async function changePassword(req, res, next) {
    try{
        await authService.changePassword(
            req.user.email, 
            req.body.oldPassword, 
            req.body.newPassword);
        res.status(200).json({
            success: true,
            message: "Password changed"
        });
    }
    catch(err){
        next(err);
    }
};

// Update User Name
async function changeUserName(req, res, next) {
    try{
        await authService.changeUserName(
            req.user.userName,
            req.body.newUserName
        );
        res.status(200).json({
            success: true, 
            message: "Username changed"
        });
    }
    catch(err){
        next(err);
    }
};

// update Email
async function changeEmail(req, res, next) {
    try{
        await authService.changeEmail(
            req.user.email,
            req.body.newEmail,
        );
        res.status(200).json({
            success: true,
            message: "Email changed"
        });
    }
    catch(err){
        next(err);
    }
};



