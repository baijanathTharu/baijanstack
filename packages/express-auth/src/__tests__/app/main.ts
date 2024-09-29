import { config } from 'dotenv';

config({
  path: '.env',
});

import express, { NextFunction, Request, Response } from 'express';
import cookieParser from 'cookie-parser';

import { RouteGenerator, TConfig } from '../../index';
import {
  LoginPersistor,
  LogoutPersistor,
  MeRoutePersistor,
  RefreshPersistor,
  ResetPasswordPersistor,
  SignUpPersistor,
  VerifyEmailPersistor,
} from '../app/auth';

const PORT = 4000;

async function main() {
  const app = express();

  app.use(express.json());

  app.use(cookieParser());

  app.get('/ping', (req, res) => {
    res.send('hello from server');
  });

  const routeGenerator = new RouteGenerator(app);

  // sign up route
  const signUpPersistor = new SignUpPersistor();
  routeGenerator.createSignUpRoute(signUpPersistor);

  // login route
  const loginPersistor = new LoginPersistor();
  routeGenerator.createLoginRoute(loginPersistor);

  // logout route
  const logoutPersistor = new LogoutPersistor();
  routeGenerator.createLogoutRoute(logoutPersistor);

  // refresh route
  const refreshPersistor = new RefreshPersistor();
  routeGenerator.createRefreshRoute(refreshPersistor);

  // reset password route
  const resetPasswordPersistor = new ResetPasswordPersistor();
  routeGenerator.createResetPasswordRoute(resetPasswordPersistor);

  // me route
  const meRoutePersistor = new MeRoutePersistor();
  routeGenerator.createMeRoute(meRoutePersistor);

  // verify email route
  const verifyEmailPersistor = new VerifyEmailPersistor();
  routeGenerator.createVerifyEmailRoute(verifyEmailPersistor);

  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    console.error('final error');
    res.status(500).json({
      message: err.message,
    });
  });

  app.listen(PORT, () => {
    console.log(`Started on ${PORT}`);
  });
}

main()
  .then(() => {
    console.log('init');
  })
  .catch((e) => {
    console.error(e);
  });
