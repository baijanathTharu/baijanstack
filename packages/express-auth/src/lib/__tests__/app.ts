import express from 'express';
import cookieParser from 'cookie-parser';
import { config, googleConfig } from './config';
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
  GoogleOAuthHandler,
} from './handlers';
import { GoogleAuthGenerator } from '../oauth/google';

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
const oAuthHandler = new GoogleOAuthHandler();

const googleGenerator = new GoogleAuthGenerator(
  app,
  {
    ...config,
    ...googleConfig,
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
});

app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});
