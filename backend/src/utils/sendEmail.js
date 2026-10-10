const BREVO_URL = "https://api.brevo.com/v3/smtp/email";

const sendEmail = async ({ to, subject, html }) => {
  const response = await fetch(BREVO_URL, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "api-key": process.env.BREVO_API_KEY,
    },
    body: JSON.stringify({
      sender: {
        name: process.env.EMAIL_FROM_NAME || "Nova",
        email: process.env.EMAIL_FROM,
      },
      to: [{ email: to }],
      subject,
      htmlContent: html,
    }),
  });

  if (!response.ok) {
    throw new Error(`Email request failed with status ${response.status}`);
  }
};

export const sendOtpEmail = (to, otp) =>
  sendEmail({
    to,
    subject: "Your Nova recovery code",
    html: `
      <div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px">
        <h2 style="margin:0 0 12px">Check your inbox.</h2>
        <p style="color:#444">Use this 6-digit code to reset your Nova password.</p>
        <p style="font-size:32px;letter-spacing:8px;font-weight:700;margin:20px 0">${otp}</p>
        <p style="color:#666;font-size:13px">This code expires in 10 minutes. If you didn't request it, you can ignore this email.</p>
      </div>
    `,
  });

export default sendEmail;