import nodemailer from "nodemailer";


const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

const sendEmail = async (subscribers, subject, message) => {
  await transporter.sendMail({
    from: process.env.SMTP_USER,
    to: subscribers.map((subscriber) => subscriber.email).join(","),
    subject: subject,
    text: message,
  });
};

export { sendEmail };
