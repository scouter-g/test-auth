const { app } = require('@azure/functions');
const { TableClient } = require('@azure/data-tables');

app.http('login', {
    methods: ['POST'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        try {
            // 1. Validate environment configuration safely inside the try block
            const connectionString = process.env.CUSTOM_STORAGE_CONNECTION;
            if (!connectionString) {
                context.error("CRITICAL CONFIG ERROR: CUSTOM_STORAGE_CONNECTION environment variable is missing!");
                return { status: 500, jsonBody: { error: "Backend configuration error. Connection string missing." } };
            }

            // 2. Safe client initialization
            const client = TableClient.fromConnectionString(connectionString, "Users");
            
            // 3. Process the JSON payload safely
            const body = await request.json();
            const { email, password } = body;

            if (!email || !password) {
                return { status: 400, jsonBody: { error: "Email and password are required." } };
            }

            // 4. Query the Users table
            const user = await client.getEntity("users", email.toLowerCase().trim());

            if (user.Password === password) {
                return {
                    status: 200,
                    jsonBody: {
                        message: "Success",
                        email: user.rowKey,
                        token: "mock-jwt-token-xyz-2026"
                    }
                };
            } else {
                return { status: 401, jsonBody: { error: "Invalid credentials." } };
            }

        } catch (error) {
            // Catch data lookups missing from table rows safely
            if (error.statusCode === 404) {
                return { status: 401, jsonBody: { error: "Invalid credentials." } };
            }
            
            // Catch connection formatting errors safely
            context.error(`API Runtime Exception: ${error.message}`);
            return { status: 500, jsonBody: { error: `Server error: ${error.message}` } };
        }
    }
});
