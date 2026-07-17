const {mail, env} = require("../config");

const sendPasswordRecoveryEmail = async(email, token)=>{
    await mail.sendMail({
        from : env.email.from,
        to: email,
        subject: "forgot password",
        html: `
            <h3>Reset Password</h3>
            <p>Use this link to reset you password</p>
            <p>${token}</p>
        `
    });
};

const sendPasswordResetConfirmationEmail = async (email) =>{
    await mail.sendMail({
        from: env.email.from,
        to: email,
        subject: "password reset successful",
        html: `
            <h3> Password reset successful</h3>
            <p>your password has been reset successfully</p>
        `
    });
};

module.exports = {
    sendPasswordRecoveryEmail, 
    sendPasswordResetConfirmationEmail
};
