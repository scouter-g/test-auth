const { TableClient } = require("@azure/data-tables");

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

    let client;
    try {
        const connectionString = process.env.STORAGE_CONNECTION_STRING;
        client = TableClient.fromConnectionString(connectionString, "Users");
    } catch (err) {
        context.res = {
            status: 500,
            body: {
                error: "Failed to create TableClient",
                message: err.message
            }
        };
        return;
    }

    let user;
    try {
        user = await client.getEntity("user", lowerEmail);
    } catch (err) {
        context.res = {
            status: 401,
            body: "Invalid credentials (user not found)"
        };
        return;
    }

    // CLEAR TEXT PASSWORD CHECK
    if (password !== user.passwordHash) {
        context.res = {
            status: 401,
            body: "Invalid credentials (password mismatch)"
        };
        return;
    }

    context.res = {
        status: 200,
        body: {
            message: "Login successful",
            email: user.RowKey,
            role: user.role,
            displayName: user.displayName,
            mustReset: user.mustReset
        }
    };
};
