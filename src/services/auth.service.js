const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const { User, RefreshToken} = require("../models");
const { logger, evn} = require("../config");
const emailService = require("./email.service");
const { env } = require("process");
const { devNull } = require("os");

// signup and account verification functions
async function signup({userName, email, password}){
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
        userName,
        email,
        password: hashedPassword
    });
    return user;
};

async function sendVerificationEmail(user){
    const {token, hashedToken} = generateToken();
    await user.update({
        verificationToken: hashedToken,
        verificationTokenExpiresAt: new Date(Date.now() + 15*60*1000)
    });
    emailService.sendAccountVerificationEmail(user.email, token);
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
// Generate Tokens
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

    if (!storedToken) throwError("Invalid Refreshtoken", 400);
    if (storedToken.expiresAt < new Date()) throwError("refreshtoken has expired", 400);

    const payload = jwt.verify(
        refreshToken,
        env.jwt.refreshSecret
    );
    const user = await User.findByPk(payload.id);
    if (!user) throwError("User not found", 404);

    return {accessToken: generateAccessToken(user)};
}


class AuthService {
    // Login
    async login({ email, password }) {
        const user = await User.findOne({ 
                where: { email: email } 
            }
        );
        if (!user) this._throwError(`User with email ${email} not found`, 404);

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) this._throwError("Invalid password", 401);

        const accessToken = this.generateAccessToken(user);
        const refreshToken = this.generateRefreshToken(user);

        await User_refresh_token.create({
            user_id: user.id,
            token: refreshToken,
            expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) 
        });
        return { 
            accessToken, 
            refreshToken,
            user: { 
                id: user.id, 
                userName: user.userName, 
                email 
            }
        };
    }

    // Refresh Token
    async refreshToken(refreshToken) {
        const token = await User_refresh_token.findOne({ 
            where: 
            { 
                token: refreshToken, 
                revoked_at: null 
            } 
        });
        if (!token) this._throwError("Invalid refresh token", 401);
        if (token.expires_at < new Date()) this._throwError("Refresh token expired", 401);

        let decoded;
        try {
            decoded = jwt.verify(refreshToken, jwtConfig.refreshToken.secret);
        } catch {
            this._throwError("Invalid refresh token", 401);
        }

        const user = await User.findByPk(decoded.id);
        if (!user) this._throwError("User not found", 404);

        return { accessToken: this.generateAccessToken(user) };
    }

    // Logout
    async logout(refreshToken) {
        const token = await User_refresh_token.findOne({ where: { token: refreshToken } });
        if (token) await token.update({ revoked_at: new Date() });

        logger.info("User logged out successfully");
    }

    // Forgot Password
    async forgotPassword(email) {
        const user = await User.findOne({ where: { email } });
        if (!user) return;

        const resetToken = crypto.randomBytes(32).toString("hex");
        const tokenHash = crypto.createHash("sha256").update(resetToken).digest("hex");

        await User_password_reset.create({
            user_id: user.id,
            token: tokenHash,
            expires_at: new Date(Date.now() + 5 * 60 * 1000) 
        });

        await emailService.sendPasswordRecoveryEmail(user.email, resetToken);
        logger.info(`Password recovery email sent to ${email}`);
    }

    // Reset Password
    async resetPassword(token, newPassword) {
        const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

        const resetRecord = await User_password_reset.findOne({ 
            where: { 
                token: tokenHash, 
                used_at: null 
            } 
        });
        if (!resetRecord) this._throwError("Invalid reset token", 400);
        if (resetRecord.expires_at < new Date()) this._throwError("Reset token expired", 400);

        const user = await User.findByPk(resetRecord.user_id);
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await user.update({ 
            password: hashedPassword 
        });
        await resetRecord.update({ 
            used_at: new Date() 
        });

        await emailService.sendPasswordResetConfirmationEmail(user.email);
        logger.info(`Password reset for ${user.email}`);
    }

    // Delete Account
    async deleteAccount(userId) {
        const user = await User.findByPk(userId);
        if (!user) this._throwError("User not found", 404);

        await User_refresh_token.destroy({ 
            where:{ 
                user_id: userId 
            } 
        });
        await User_password_reset.destroy({ 
            where: 
            { 
                user_id: userId 
            } 
        });
        await user.destroy();
        logger.info(`User deleted account: ${user.email}`);
    }

    // Error Helper
    _throwError(message, statusCode) {
        const err = new Error(message);
        err.statusCode = statusCode;
        throw err;
    }



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



