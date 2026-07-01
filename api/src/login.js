const { app } = require('@azure/functions');
const { TableClient } = require('@azure/data-tables');

// Pulls connection string dynamically from SWA environment variables
const connectionString = process.env.CUSTOM_STORAGE_CONNECTION;
const client = TableClient.fromConnectionString(connectionString, "Users");

app.http('login', {
    methods: ['POST'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        try {
            const body = await request.json();
            const { email, password } = body;

            if (!email || !password) {
                return { status: 400, jsonBody: { error: "Email and password are required." } };
            }

            // Instantly look up the user by PartitionKey ("users") and RowKey (email)
            const user = await client.getEntity("users", email.toLowerCase().trim());

            // Simple validation (Upgrade to Hashing in production!)
            if (user.Password === password) {
                return {
                    status: 200,
                    jsonBody: {
                        message: "Success",
                        email: user.rowKey,
                        token: "mock-jwt-token-xyz-2026" // Replace with real generated JWT if needed
                    }
                };
            } else {
                return { status: 401, jsonBody: { error: "Invalid credentials." } };
            }

        } catch (error) {
            // Azure Tables throws a 404 if the exact RowKey isn't found
            if (error.statusCode === 404) {
                return { status: 401, jsonBody: { error: "Invalid credentials." } };
            }
            
            context.log(`Error: ${error.message}`);
            return { status: 500, jsonBody: { error: "Internal server error." } };
        }
    }
});
