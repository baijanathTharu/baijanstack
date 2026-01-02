import express from 'express';
import cookieParser from 'cookie-parser';
import { config, githubConfig, googleConfig } from './config';
import { RouteGenerator, validateAccessToken } from '../auth';
import { EmailNotificationService } from './notifier';
import { initAuth } from '../init-auth';
import {
  SignUpHandler,
  LoginHandler,
  LogoutHandler,
  RefreshHandler,
  ResetPasswordHandler,
  MeRouteHandler,
  VerifyEmailHandler,
  ForgotPasswordHandler,
  SendOtpHandler,
  OAuthHandler,
} from './handlers';
import { GoogleAuthGenerator } from '../oauth/google';
import { GithubAuthGenerator } from '../oauth/github';

const app = express();
app.use(express.json());

app.use(cookieParser());

console.log('----config----', config);

app.get('/', (req, res) => {
  res.send('Express Auth Service is running!');
});

app.get('/protected', validateAccessToken, (req, res) => {
  // @ts-expect-error need to make express.d.ts
  const user = req.decodedAccessToken;
  console.log('Protected route accessed', user);
  res.json({
    message: 'This is a protected route',
    user: user,
  });
});

const routeGenerator = new RouteGenerator(
  app,
  new EmailNotificationService(),
  config
);

const oAuthHandler = new OAuthHandler();

const googleGenerator = new GoogleAuthGenerator(
  app,
  {
    ...config,
    ...googleConfig,
  },
  oAuthHandler
);

const githubGenerator = new GithubAuthGenerator(
  app,
  {
    ...config,
    ...githubConfig,
  },
  oAuthHandler
);

initAuth({
  routeGenerator,
  signUpHandler: new SignUpHandler(),
  loginHandler: new LoginHandler(),
  logoutHandler: new LogoutHandler(),
  refreshHandler: new RefreshHandler(),
  resetPasswordHandler: new ResetPasswordHandler(),
  meRouteHandler: new MeRouteHandler(),
  verifyEmailHandler: new VerifyEmailHandler(),
  forgotPasswordHandler: new ForgotPasswordHandler(),
  sendOtpHandler: new SendOtpHandler(),
  googleOAuth: {
    generator: googleGenerator,
    oAuthHandler,
  },
  githubOAuth: {
    generator: githubGenerator,
    oAuthHandler,
  },
});

app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});
