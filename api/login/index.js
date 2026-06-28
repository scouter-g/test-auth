const crypto = require("crypto");

// Replace with your real user table lookup
async function getUserByEmail(email) {
    // Hardcoded test user
    if (email === "test@example.com") {
        return {
            id: 1,
            email: "test@example.com",
            password: "Password123" // plain text for demo only
        };
    }
    return null;
}

function base64url(input) {
    return Buffer.from(input)
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

function signJWT(payload, secret) {
    const header = {
        alg: "HS256",
        typ: "JWT"
    };

    const headerEncoded = base64url(JSON.stringify(header));
    const payloadEncoded = base64url(JSON.stringify(payload));

    const data = `${headerEncoded}.${payloadEncoded}`;
    const signature = crypto
        .createHmac("sha256", secret)
        .update(data)
        .digest("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");

    return `${data}.${signature}`;
}

module.exports = async function (context, req) {
    const { email, password } = req.body || {};

    if (!email || !password) {
        context.res = {
            status: 400,
            body: "Email and password required"
        };
        return;
    }

    const user = await getUserByEmail(email);

    if (!user || user.password !== password) {
        context.res = {
            status: 401,
            body: "Invalid credentials"
        };
        return;
    }

    const secret = process.env.JWT_SECRET || "dev-secret";

    const token = signJWT(
        {
            sub: user.id,
            email: user.email,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
        },
        secret
    );

    context.res = {
        status: 200,
        body: { token }
    };
};
