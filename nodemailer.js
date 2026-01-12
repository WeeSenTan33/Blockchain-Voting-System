import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_USER, // e.g. 2230300@alfateh.upnm.edu.my
    pass: process.env.SMTP_PASS  // your password or app password
  }
});

export const sendOTP = (recipientEmail, otp) => {
  const mailOptions = {
    from: `"Voting System" <${process.env.SMTP_USER}>`,
    to: recipientEmail,
    subject: 'Your OTP Code for Login',
    html: `
     <div style="background-color: #111827; padding: 40px 20px; color: #ffffff; font-family: Arial, sans-serif; text-align: center;">
      <div style="max-width: 500px; margin: auto; background-color: #1f2937; padding: 30px; border-radius: 8px;">
        <h2 style="margin-bottom: 20px; font-size: 20px; color: rgba(255, 255, 255, 1);">Your OTP Code</h2>
        <div style="background-color: #374151; padding: 16px 32px; border-radius: 6px; display: inline-block;">
          <span style="font-size: 36px; font-weight: bold; letter-spacing: 4px; color: #2c8fdbff;">${otp}</span>
        </div>
        <p style="margin-top: 24px; font-size: 14px; color: #d1d5db;">
          This is an automatically generated email.
        </p>
      </div>
    </div>
      `
  };

  return transporter.sendMail(mailOptions)
    .then(info => {
      console.log('✅ Email sent:', info.response);
    })
    .catch(error => {
      console.error('❌ Email error:', error);
    });
};
