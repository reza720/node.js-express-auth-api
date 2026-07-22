const {mailTransporter, env} = require("../config");

const sendPasswordResetEmail = async(email, token)=>{
    const link = `${env.frontEnd.url}/reset?token=${token}`;
    await mailTransporter.sendMail({
        from : env.email.from,
        to: email,
        subject: "Reset Password",
        html: `
            <p>Click this link to reset you password</p>
            <a href="${link}">Reset Password</a>
            <p>This link will expire in 15 minutes</p>
        `
    });
};

const sendAccountVerificationEmail = async (email, token) =>{
    const link = `${env.frontEnd.url}/verify?token=${token}`
    await mailTransporter.sendMail({
        from: env.email.from,
        to: email,
        subject: "Verify Account",
        html: `
            <p>Click this link to verify your email address</p>
            <a href="${link}">Verify</a>
        `
    });
};

module.exports = {
    sendPasswordResetEmail,
    sendAccountVerificationEmail
};
