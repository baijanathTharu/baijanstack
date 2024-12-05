import request from 'supertest';
import express from 'express';
import cookieParser from 'cookie-parser';

import { config } from './config';
import { initAuth } from '../init-auth';
import { RouteGenerator } from '../auth';
import {
  ForgotPasswordHandler,
  LoginHandler,
  LogoutHandler,
  MeRouteHandler,
  RefreshHandler,
  ResetPasswordHandler,
  SendOtpHandler,
  SignUpHandler,
  VerifyEmailHandler,
} from './handlers';
import { EmailNotificationService } from './notifier';
import { LoginResponseCodes, SignUpResponseCodes } from '../response-codes';

const john = {
  name: 'john',
  email: 'john@test.com',
  password: 'john',
};

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
    });
  });

  it('should not be able to sign up without an email', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/signup`)
      .send({ name: john.name });
    expect(res.status).toBe(400);
  });

  it('should not be able to sign up without a password', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/signup`)
      .send({ email: john.email });
    expect(res.status).toBe(400);
  });

  it('should be able to sign up', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/signup`)
      .send({ email: john.email, password: 'john' });
    expect(res.status).toBe(201);
    expect(res.body).toEqual({
      message: expect.any(String),
      code: SignUpResponseCodes.USER_CREATED,
    });
  });

  it('should not be able to sign up if user already exists', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/signup`)
      .send({ email: john.email, password: 'john' });
    expect(res.status).toBe(409);
    expect(res.body).toEqual({
      message: expect.any(String),
      code: SignUpResponseCodes.USER_ALREADY_EXISTS,
    });
  });

  it('should not be able to login without an email', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/login`)
      .send({ name: john.name });
    expect(res.status).toBe(400);
  });

  it('should not be able to login without a password', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/login`)
      .send({ email: john.email });
    expect(res.status).toBe(400);
  });

  it('should not be able to login if user does not exist', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/login`)
      .send({ email: 'john2@test.com', password: 'john' });
    expect(res.status).toBe(409);
    expect(res.body).toEqual({
      message: expect.any(String),
      code: LoginResponseCodes.PASSWORD_OR_EMAIL_INCORRECT,
    });
  });

  it('should not be able to login if password is incorrect', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/login`)
      .send({ email: john.email, password: 'john2' });
    expect(res.status).toBe(409);
    expect(res.body).toEqual({
      message: expect.any(String),
      code: LoginResponseCodes.PASSWORD_OR_EMAIL_INCORRECT,
    });
  });

  it('should be able to login', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/login`)
      .send({ email: john.email, password: john.password });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      message: expect.any(String),
      code: LoginResponseCodes.LOGIN_SUCCESS,
    });

    expect(res.header['set-cookie']).toBeDefined();
  });
});
