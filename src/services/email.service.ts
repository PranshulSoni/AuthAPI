import { AuthConfig } from '../types/index.js'

export async function sendVerificationEmail(emailConfig: NonNullable<AuthConfig['email']>, to: string, verificationUrl: string) {
    if (emailConfig.provider != "resend") {
        throw new Error("Email provider currently Unsupported");
    }
    const response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${emailConfig.apiKey}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            from: emailConfig.from,
            to,
            subject: "Verify your email",
            html: `<p>Verify your email by clicking on the link below:</p><a href="${verificationUrl}">${verificationUrl}</a>`
        })
    });
    if (!response.ok) {
        throw new Error("Failed to send verification email");
    }
}


export async function sendPasswordResetEmail(
    emailConfig: NonNullable<AuthConfig['email']>,
    to: string,
    resetUrl: string
) {
    if (emailConfig.provider != "resend") {
        throw new Error("Email provider currently Unsupported");
    }

    const response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${emailConfig.apiKey}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            from: emailConfig.from,
            to,
            subject: "Reset your password",
            html: `<p>Reset your password by clicking on the link below:</p><a href="${resetUrl}">${resetUrl}</a>`
        })
    });

    if (!response.ok) {
        throw new Error("Failed to send password reset email");
    }
}