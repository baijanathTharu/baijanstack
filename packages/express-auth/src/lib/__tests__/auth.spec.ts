import request from 'supertest';
import express from 'express';
import cookieParser from 'cookie-parser';

import { config, githubConfig, googleConfig } from './config';
import { initAuth } from '../init-auth';
import { RouteGenerator, validateAccessToken } from '../auth';
import {
  ForgotPasswordHandler,
  LoginHandler,
  LogoutHandler,
  MeRouteHandler,
  OAuthHandler,
  RefreshHandler,
  ResetPasswordHandler,
  SendOtpHandler,
  SignUpHandler,
  VerifyEmailHandler,
} from './handlers';
import { EmailNotificationService } from './notifier';
import { LoginResponseCodes, SignUpResponseCodes } from '../response-codes';
import { GoogleAuthGenerator } from '../oauth/google';
import passport from 'passport';
import { GithubAuthGenerator } from '../oauth/github';

/**
 * set the env variable
 */
process.env['TOKEN_SECRET'] = config.TOKEN_SECRET;

const john = {
  name: 'john',
  email: 'john@test.com',
  password: 'john',
};

describe('expressAuth', () => {
  let app: express.Application;

  beforeAll(() => {
    jest
      .spyOn(passport, 'authenticate')
      .mockImplementation((strategy, options) => {
        return (req: any, res: any, next: any) => {
          // Simulate successful authentication
          req.user = { id: 'google-user', email: john.email };
          next();
        };
      });

    app = express();
    app.use(express.json());

    app.use(cookieParser());

    console.log('----config----', config);

    app.get('/', (req, res) => {
      res.send('Express Auth Service is running!');
    });

    app.get('/protected', validateAccessToken, (req, res) => {
      // @ts-expect-error need to make express.d.ts
      const user = req.decodedAccessToken;
      res.json({
        message: 'This is a protected route',
        user: user,
      });
    });

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
      googleOAuth: {
        generator: googleGenerator,
        oAuthHandler,
      },
      githubOAuth: {
        generator: githubGenerator,
        oAuthHandler,
      },
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
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
      .send({ email: john.email, password: john.password, name: john.name });
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

  it('should be able to verify email with test otp code', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/verify-email`)
      .send({ email: john.email, otp: config.TEST_OTP });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      message: expect.any(String),
      code: 'VERIFY_EMAIL_SUCCESS',
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
      data: {
        accessToken: expect.any(String),
        refreshToken: expect.any(String),
        user: {
          name: john.name,
          email: john.email,
          is_email_verified: true,
          password: expect.any(String),
        },
      },
    });

    expect(res.header['set-cookie']).toBeDefined();

    // send token in headers to check if user is logged in
    const meRes = await request(app)
      .get(`${config.BASE_PATH}/me`)
      .set('x-access-token', res.body.data.accessToken);

    expect(meRes.status).toBe(200);
  });

  it('should not refresh token without a refresh token in headers or cookies', async () => {
    const res = await request(app).post(`${config.BASE_PATH}/refresh`);
    expect(res.status).toBe(400);
    expect(res.body).toEqual({
      message: 'Refresh token not found in the header or cookie',
      code: expect.any(String),
    });
  });

  it('should not refresh token with an invalid refresh token', async () => {
    const res = await request(app)
      .post(`${config.BASE_PATH}/refresh`)
      .set('x-refresh-token', 'invalid-token');
    expect(res.status).toBe(400);
    expect(res.body).toEqual({
      message: 'Token is invalid',
      code: expect.any(String),
    });
  });

  it('should refresh token successfully with a valid refresh token', async () => {
    // First, login to get a valid refresh token
    const loginRes = await request(app)
      .post(`${config.BASE_PATH}/login`)
      .send({ email: john.email, password: john.password });
    expect(loginRes.status).toBe(200);

    const refreshToken = loginRes.body.data.refreshToken;

    // Use the refresh token to refresh tokens
    const refreshRes = await request(app)
      .post(`${config.BASE_PATH}/refresh`)
      .set('x-refresh-token', refreshToken);

    expect(refreshRes.status).toBe(200);
    expect(refreshRes.body).toEqual({
      message: 'Refreshed token successfully!!',
      code: expect.any(String),
      data: {
        accessToken: expect.any(String),
        refreshToken: expect.any(String),
      },
    });

    expect(refreshRes.header['set-cookie']).toBeDefined();
  });

  // TODO: add more test for other cases
  // failures and different scenarios
  it('should mock Google OAuth callback and return user', async () => {
    const res = await request(app).get(`${config.BASE_PATH}/google/callback`);

    expect(res.status).toBe(302);
    // @ts-expect-error may need typing
    const location = res.header.location;
    expect(location).toBe(googleConfig.GOOGLE_SUCCESS_REDIRECT_URI);
  });

  it('should mock Github OAuth callback and return user', async () => {
    const res = await request(app).get(`${config.BASE_PATH}/github/callback`);

    expect(res.status).toBe(302);
    // @ts-expect-error may need typing
    const location = res.header.location;
    expect(location).toBe(githubConfig.GITHUB_SUCCESS_REDIRECT_URI);
  });
});
