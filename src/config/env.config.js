require ('dotenv').config();

const env={
    server:{
        port: Number(process.env.PORT) || 5000,
    },
    database: {
        dbName:process.env.DB_NAME,
        user:process.env.DB_USER,
        password:process.env.DB_PASSWORD,
        host:process.env.DB_HOST
    },
    jwt:{
        accessSecret:process.env.JWT_ACCESS_SECRET,
        accessSecretExpiresAt:process.env.JWT_ACCESS_EXPIRESAT,
        refreshSecret:process.env.JWT_REFRESH_SECRET,
        refreshSecretExpiresAt:process.env.JWT_REFRESH_EXPIRESAT
    },
    email:{
        host:process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT),
        secure:process.env.SMTP_SECURE,
        user:process.env.SMTP_USER,
        password:process.env.SMTP_PASSWORD,
        from:process.env.EMAIL_FROM,
    },
    frontEnd:{
        url:process.env.FRONTEND_URL,
    }
};

module.exports = env;