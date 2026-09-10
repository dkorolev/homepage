import { createApp } from './app.js';

const port = Number(process.env.PORT || 3100);
const development = process.env.NODE_ENV !== 'production';
const settings = {
  development,
  currentOrigin: process.env.CURRENT_ORIGIN || (development ? `http://127.0.0.1:${port}` : 'https://current.ai'),
  dimaOrigin: process.env.DIMA_ORIGIN || (development ? `http://localhost:${port}` : 'https://dima.ai'),
  backchannel: process.env.CURRENT_BACKCHANNEL || `http://127.0.0.1:${port}`,
  googleIssuer: 'https://accounts.google.com',
  googleId: process.env.GOOGLE_CLIENT_ID, googleSecret: process.env.GOOGLE_CLIENT_SECRET,
  githubId: process.env.GITHUB_CLIENT_ID, githubSecret: process.env.GITHUB_CLIENT_SECRET,
  enterpriseIssuer: process.env.ENTERPRISE_OIDC_ISSUER,
  enterpriseId: process.env.ENTERPRISE_OIDC_CLIENT_ID, enterpriseSecret: process.env.ENTERPRISE_OIDC_CLIENT_SECRET,
  jwksFile: process.env.CURRENT_JWKS_FILE,
  registrationToken: process.env.CURRENT_REGISTRATION_TOKEN,
  clientsFile: process.env.CURRENT_CLIENTS_FILE,
};
const { app } = await createApp(settings);
const server = app.listen(port, '127.0.0.1', () => console.log(`Current demos listening on 127.0.0.1:${port}`));
server.requestTimeout = 30000;
server.headersTimeout = 15000;
for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5000).unref();
});
