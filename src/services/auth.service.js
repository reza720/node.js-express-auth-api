// Fix  service and controllers for input and return 
// Seding in heading or body, or user or what else

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const { User, RefreshToken} = require("../models");
const { logger, evn} = require("../config");
const emailService = require("./email.service");

// Register a new user
async function signup({userName, email, password}){
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
        userName,
        email,
        password: hashedPassword
    });
    return {
        id: user.id,
        userName: user.userName,
        email: user.email
    };
};

// Send email verification request
async function requestEmailVerification(userId){
    const user = await User.findByPk(userId);
    if(!user) throwError("User not found", 404);
    if(user.isVerified) throwError ("Email is already verified", 400);

    const {token, hashedToken} = generateToken();
    await user.update({
        verificationToken: hashedToken,
        verificationTokenExpiresAt: new Date(Date.now() + 15*60*1000)
    });

    await emailService.sendAccountVerificationEmail(user.email, token);
};

// Verify email using token
async function  verifyEmailToken(token) {
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
        where: {verificationToken:hashedToken}
    });
    if(!user) throwError("Invalid token", 400);
    if(user.verificationTokenExpiresAt < new Date()) throwError("Token has expired", 400);

    await user.update({
        isVerified: true,
        verificationToken: null,
        verificationTokenExpiresAt: null
    });
    return {
        id: user.id,
        userName: user.userName,
        email: user.email,
        isVerified: user.isVerified
    };
}

// Login 
async function login({email, password}) {
    const user = await User.findOne({
        where: {email}
    });
    
    if (!user) throwError(`User with ${email} email not found`, 404);
    const isPassValid = await bcrypt.compare(password, user.password);
    if(!isPassValid) throwError("Email or password is not correct", 401);
    if(!user.isVerified) throwError("Verify your email", 401);

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
    const {exp} = jwt.verify(refreshToken, env.jwt.refreshSecret);

    await RefreshToken.create({
        userId: user.id,
        tokenHash: refreshTokenHash,
        expiresAt: new Date(exp * 1000)
    });
    
    return {
        user: {
            id: user.id,
            userName: user.userName,
            email: user.email
        },
        accessToken,
        refreshToken
    }
}
async function refreshAccessToken(refreshToken) {
    const tokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    const storedToken = await RefreshToken.findOne({
        where: {
            tokenHash,
            revokedAt: null,
        },
    });

    if (!storedToken) throwError("Invalid Refreshtoken", 401);
    if (storedToken.expiresAt < new Date()) throwError("refreshtoken has expired", 401);

    const payload = jwt.verify(
        refreshToken,
        env.jwt.refreshSecret
    );
    const user = await User.findByPk(payload.id);
    if (!user) throwError("User not found", 404);

    const accessToken = generateAccessToken(user);
    return {accessToken};
}

// Update email, password, and userName
async function changePassword(email, oldPassword, newPassword) {
    const user = await User.findOne({
        where:{email}
    });
    if(!user) throwError("User not found", 404);

    const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);
    if(!isOldPasswordValid) throwError("Invalid password", 401);

    const newPasswordHashed = await bcrypt.hash(newPassword, 10);

    await user.update({
        password:newPasswordHashed
    });
};

async function changeUserName(oldUserName, newUserName) {
    const user = await User.findOne({
        where:{userName:oldUserName}
    });

    if(!user) throwError("User not found", 404);

    await user.update({
        userName: newUserName
    });
};

async function changeEmail(oldEmail, newEmail) {
    const user = await User.findOne({
        where:{email:oldEmail}
    });

    if(!user) throwError("User not found", 404);

    await user.update({
        email:newEmail
    });
}

// Logout
async function logout(refreshToken) {
    const hashedToken = crypto.createHash("sha256").update(refreshToken).digest("hex");
    const storedToken = await RefreshToken.findOne({
        where:{
            tokenHash: hashedToken,
            revokedAt: null
        }
    });
    
    if(!storedToken) throwError("Invalid refresh token", 401);

    await storedToken.update({
        revokedAt: new Date()
    });
    
    return {
        message: "User logout"
    };
}

// Handle forgot and reset password
async function sendForgotPasswordEmail(user) {    
    const {token, hashedToken} = generateToken();
    await User.update({
        resetPasswordToken: hashedToken,
        resetPasswordTokenExpiresAt: new Date(new Date() +  + 15 * 60 * 1000)
    });

    emailService.sendPasswordResetEmail(email, token);
    return {
        message: "password reset email sent"
    };
};

async function resetPassword(token, newPassword) {
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
        where:{resetPasswordToken: hashedToken}
    });
    
    if(!user) throwError("Invalid token", 400);
    if(user.resetPasswordTokenExpiresAt < new Date()) throwError("Token has expired", 400);

    const newPasswordHashed = await bcrypt.hash(newPassword, 10);
    await user.update({
        password: newPasswordHashed,
        resetPasswordToken: null,
        resetPasswordTokenExpiresAt: null
    });
    
    return {
        message: "Password changed"
    };
};

async function resendForgotPasswordEmail(email) {
    const user = await User.findOne({
        where: { email }
    });

    if (!user)  throwError("User not found", 404);

    const {token, hashedToken} = generateToken();

    await user.update({
        resetPasswordToken: hashedToken,
        resetPasswordTokenExpiresAt: new Date(Date.now() + 15 * 60 * 1000)
    });

    await emailService.sendPasswordResetEmail(user.email,token);

    return {
        message: "Password reset email sent"
    };
}

// Delete user account
async function deleteUser(email) {
    const user = await User.findOne({
        where:{email}
    });

    if(!user) throwError("User not found", 404);

    await RefreshToken.destroy({
        where:{userId:user.id}
    });
    await user.destroy();

    return {
        message: "User Deleted"
    };
};

// User Retrieval
async function getUser(userId) {
    const user = await User.findByPk(userId);
    if(!user) throwError("User not found", 404);

    return {
        id: user.id,
        userName: user.userName,
        email: user.email
    };
}



// Utility Functions

// Generates secure tokens for email verification and reset password
function generateToken(){
    const token = crypto.randomBytes(16).toString("hex");
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    return {
        token,
        hashedToken
    }
};

// Creates application errors with HTTP status codes
function throwError(message, code){
    const err = new Error(message);
    err.status = code;
    throw err;
}

// Generates JWT access tokens
function generateAccessToken(user){
    return jwt.sign(
        {
            id:user.id,
            userName: user.userName,
            email: user.email
        },
        env.jwt.accessToken,
        {
            expiresIn: env.jwt.accessSecretExpiresAt
        }
    );
}

// Generates JWT refresh tokens
function generateRefreshToken(user){
    return jwt.sign(
        {
            id:user.id
        },
        env.jwt.refreshSecret,
        {
            expiresIn: env.jwt.refreshSecretExpiresAt
        }
    );
}

module.exports = {
    signup,
    requestEmailVerification,
    verifyEmailToken,
    login,
    refreshAccessToken,
    changeEmail,
    changePassword,
    changeUserName,
    logout,
    sendForgotPasswordEmail,
    resetPassword,
    resendForgotPasswordEmail,
    deleteUser,
    getUser
};


