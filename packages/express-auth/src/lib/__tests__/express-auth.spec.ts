import request from 'supertest';
import express from 'express';
import cookieParser from 'cookie-parser';

import { config } from './config';
import { RouteGenerator } from '../express-auth';
import {
  LoginPersistor,
  LogoutPersistor,
  MeRoutePersistor,
  RefreshPersistor,
  ResetPasswordPersistor,
  SignUpPersistor,
  VerifyEmailPersistor,
  TUser,
} from './persistors';
import { EmailNotificationService } from './notifier';

describe('expressAuth', () => {
  let app: express.Application;

  beforeAll(() => {
    app = express();
    app.use(express.json());

    app.use(cookieParser());

    console.log('----config----', config);

    const routeGenerator = new RouteGenerator(
      app,
      new EmailNotificationService(),
      config
    );

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

    // verify email route
    const verifyEmailPersistor = new VerifyEmailPersistor();
    routeGenerator.createVerifyEmailRoute(verifyEmailPersistor);

    // me route
    const meRoutePersistor = new MeRoutePersistor();
    routeGenerator.createMeRoute(meRoutePersistor);

    // !TODO: Verify email route redirection route
    // !TODO: forgot password route
  });

  it('should not be able to sign up without an email', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/signup`)
      .send({ name: 'john' });
    expect(res.status).toBe(400);
  });

  it('should not be able to sign up without a password', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/signup`)
      .send({ email: 'john' });
    expect(res.status).toBe(400);
  });

  it('should be able to sign up', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/signup`)
      .send({ email: 'john', password: 'john' });
    expect(res.status).toBe(201);
    expect(res.body).toEqual({
      message: 'User created',
    });
  });

  it('should not be able to sign up if user already exists', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/signup`)
      .send({ email: 'john', password: 'john' });
    expect(res.status).toBe(409);
    expect(res.body).toEqual({
      message: 'User already exists',
    });
  });
});
