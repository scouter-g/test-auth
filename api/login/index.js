const { TableClient } = require("@azure/data-tables");
const crypto = require("crypto");

// Convert to base64url for JWT
function base64url(input) {
    return Buffer.from(input)
        .toString("base64")
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

// Sign JWT using HS256
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

// PBKDF2 password verification
async function verifyPassword(password, storedHash) {
    const [method, iterations, saltHex, hashHex] = storedHash.split("$");

    if (method !== "pbkdf2") {
        throw new Error("Unsupported password hash format");
    }

    const salt = Buffer.from(saltHex, "hex");
    const expected = Buffer.from(hashHex, "hex");

    const derived = crypto.pbkdf2Sync(
        password,
        salt,
        parseInt(iterations),
        expected.length,
        "sha256"
    );

    return crypto.timingSafeEqual(derived, expected);
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

    const connectionString = process.env.STORAGE_CONNECTION_STRING;
    const tableName = "Users";

    const client = TableClient.fromConnectionString(connectionString, tableName);

    let user;
    try {
        user = await client.getEntity("user", lowerEmail);
    } catch (err) {
        // REAL DEBUG BLOCK — this will finally show the actual error
        context.res = {
            status: 500,
            body: {
                error: "Storage lookup failed",
                message: err.message,
                name: err.name,
                stack: err.stack
            }
        };
        return;
    }

    // Now verify password
    let passwordMatches = false;
    try {
        passwordMatches = await verifyPassword(password, user.passwordHash);
    } catch (err) {
        context.res = {
            status: 500,
            body: {
                error: "Password verification error",
                message: err.message,
                name: err.name,
                stack: err.stack
            }
        };
        return;
    }

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
