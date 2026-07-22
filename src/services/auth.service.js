const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const { User, RefreshToken} = require("../models");
const { logger, evn} = require("../config");
const emailService = require("./email.service");

// signup 
async function signup({userName, email, password}){
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
        userName,
        email,
        password: hashedPassword
    });
    return user;
};

// Account verification
async function sendVerificationEmail(user){
    const {token, hashedToken} = generateToken();
    await user.update({
        verificationToken: hashedToken,
        verificationTokenExpiresAt: new Date(Date.now() + 15*60*1000)
    });
    emailService.sendAccountVerificationEmail(user.email, token);
    return {
        message: "email verification sent"
    };
};

async function  verifyEmail(token) {
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    const user = User.findOne({
        where: {verificationToken:hashedToken}
    });
    if(!user) throwError("Invalid token", 400);
    if(user.verificationTokenExpiresAt < new Date()) throwError("Token has expired", 400);

    await user.update({
        isVerified: true,
        verificationToken: null,
        verificationTokenExpiresAt: null
    });
    return user;
}

async function resendVerificationEmail(email) {
    const user = await User.findOne({
        where: {email}
    });
    
    if(!user) throwError(`User with ${email} email not found`, 404);
    if(user.isVerified) throwError(`${email} is already verified`, 400);

    await sendVerificationEmail(user);
    return {
        message: "Verification email sent"
    };
}

// Login 
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
async function login({email, password}) {
    const user = await User.findOne({
        where: {email}
    });
    
    if (!user) throwError(`User with ${email} email not found`, 404);
    const isPassValid = await bcrypt.compare(user.password, password);
    if(!isPassValid) throwError("Email or password is not correct", 400);
    if(!user.isVerified) throwError("Verify your email", 400);

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    const tokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
    const {exp} = jwt.verify(refreshToken, env.jwt.refreshSecret);

    await RefreshToken.create({
        userId: user.id,
        tokenHash: tokenHash,
        expiresAt: new Date(exp * 1000)
    });
    
    return {
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

    return {accessToken: generateAccessToken(user)};
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

    return {
        message:"Password changed"
    };
};

async function changeUserName(oldUserName, newUserName) {
    const user = await User.findOne({
        where:{userName:oldUserName}
    });

    if(!user) throwError("User not found", 404);

    await user.update({
        userName: newUserName
    });

    return {
        message: "User name changed"
    };
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
// Forgot and reset password
async function forgotPassword(user) {    
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

async function resendForgotPassword(email) {
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

// Delete Users
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

// Get User
async function getUser(userId) {
    const user = await User.findByPk(userId);
    if(!user) throwError("User not found", 404);

    return {
        id: user.id,
        userName: user.userName,
        email: user.email
    };
}



// Utils
function generateToken(){
    const token = crypto.randomBytes(16).toString("hex");
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    return {
        token,
        hashedToken
    }
};

function throwError(message, code){
    const err = new Error(message);
    err.status = code;
    throw err;
}



