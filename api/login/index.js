const { TableClient } = require("@azure/data-tables");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

function base64url(input) {
    return Buffer.from(input)
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

function signJWT(payload, secret) {
    const header = { alg: "HS256", typ: "JWT" };
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

    const lowerEmail = email.toLowerCase();

    // ENV variables you will add in SWA → Configuration
    const connectionString = process.env.STORAGE_CONNECTION_STRING;
    const tableName = "Users";

    const client = TableClient.fromConnectionString(connectionString, tableName);

    let user;
    try {
        user = await client.getEntity("user", lowerEmail);
    } catch (err) {
        context.res = {
            status: 401,
            body: "Invalid credentials"
        };
        return;
    }

    const passwordMatches = await bcrypt.compare(password, user.passwordHash);

    if (!passwordMatches) {
        context.res = {
            status: 401,
            body: "Invalid credentials"
        };
        return;
    }

    const secret = process.env.JWT_SECRET || "dev-secret";

    const token = signJWT(
        {
            sub: user.RowKey,
            role: user.role,
            displayName: user.displayName,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3600
        },
        secret
    );

    context.res = {
        status: 200,
        body: {
            token,
            role: user.role,
            displayName: user.displayName,
            mustReset: user.mustReset
        }
    };
};
