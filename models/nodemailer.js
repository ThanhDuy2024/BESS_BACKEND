const nodemailer = require('nodemailer');

const sendOtpNodemailer = (userEmail, otp) => {
    const transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 587,
        secure: false, // use false for STARTTLS; true for SSL on port 465
        auth: {
            user: process.env.MAIN_MAIL,
            pass: process.env.APP_PASSWORD
        }
    });

    const mailOptions = {
        from: process.env.MAIN_MAIL,
        to: userEmail,
        subject: 'Mã OTP xác nhận!',
        html: `Mã OTP của bạn là: <b>${otp}</b> <div>Lưu ý mã OTP chỉ có hiệu lực trong vòng 1 phút</div>`
    };

    transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
            console.log('Error:', error);
        } else {
            console.log('Email sent: ', info.response);
        }
    });
}

module.exports = sendOtpNodemailer;