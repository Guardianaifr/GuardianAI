// Imported first so it runs before @elizaos/core reads LOG_LEVEL.
// Hides ElizaOS's internal logs (onboarding warnings, rate-limit retries); DEBUG=1 shows them.
if (!process.env.LOG_LEVEL) process.env.LOG_LEVEL = process.env.DEBUG ? 'info' : 'fatal'
