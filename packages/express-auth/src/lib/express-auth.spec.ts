import request from 'supertest';
import express from 'express';
import cookieParser from 'cookie-parser';

import { writeTestLogToFile } from '../test-util';

import {
  ILoginPersistor,
  ILogoutPersistor,
  ISignUpPersistor,
  RouteGenerator,
  TConfig,
} from './express-auth';

type TUser = {
  name: string;
  email: string;
  password: string;
};

type TLoginInput = Pick<TUser, 'email' | 'password'>;

const users: TUser[] = [
  {
    name: 'test',
    email: 'test@test.com',
    password: 'test',
  },
];

const config: TConfig = {
  SALT_ROUNDS: '10',
  TOKEN_SECRET: 'test',
  ACCESS_TOKEN_AGE: '15m',
  REFRESH_TOKEN_AGE: '7d',
  ACCESS_TOKEN_COOKIE_MAX_AGE: 900_000,
  REFRESH_TOKEN_COOKIE_MAX_AGE: 604_800_000,
};

class SignUpPersistor implements ISignUpPersistor {
  errors: { USER_ALREADY_EXISTS_MESSAGE?: string } = {};
  doesUserExists: (body: TUser) => Promise<boolean> = async (body) => {
    writeTestLogToFile(`doesUserExists: ${JSON.stringify(body)}`);
    const isExists = users.find(
      (user) => body.email.trim() === user.email.trim()
    );
    return !!isExists;
  };
  saveUser: (body: TUser) => Promise<void> = async (body) => {
    users.push(body);
  };
}

class LoginPersistor implements ILoginPersistor {
  errors: { PASSWORD_OR_EMAIL_INCORRECT?: string } = {
    PASSWORD_OR_EMAIL_INCORRECT: 'Password or email incorrect',
  };
  login: () => Promise<void> = async () => {
    console.log('logged in successfully!!');
  };
  doesUserExists: (body: TLoginInput) => Promise<boolean> = async (body) => {
    writeTestLogToFile(`doesUserExists: ${JSON.stringify(body)}`);
    const isExists = users.find(
      (user) => body.email.trim() === user.email.trim()
    );
    return !!isExists;
  };
  doesPasswordMatch: (body: TLoginInput) => Promise<boolean> = async (body) => {
    writeTestLogToFile(`doesPasswordMatch: ${JSON.stringify(body)}`);
    const user = users.find((user) => body.email.trim() === user.email.trim());
    return user?.password === body.password;
  };

  tokenKeysFromBody: (body: TLoginInput) => Promise<string[]> = async (
    body
  ) => {
    writeTestLogToFile(`getTokenInput: ${JSON.stringify(body)}`);
    return ['email'];
  };
}

class LogoutPersistor implements ILogoutPersistor {
  revokeTokens: () => Promise<boolean> = async () => {
    console.log('code to revoke token');
    return true;
  };
}

describe('expressAuth', () => {
  let app: express.Application;

  beforeAll(() => {
    app = express();
    app.use(express.json());

    app.use(cookieParser());

    console.log('----config----', config);

    const routeGenerator = new RouteGenerator(app, config);

    // sign up route
    const signUpPersistor = new SignUpPersistor();
    routeGenerator.createSignUpRoute(signUpPersistor);

    // login route
    const loginPersistor = new LoginPersistor();
    routeGenerator.createLoginRoute(loginPersistor);

    // logout route
    const logoutPersistor = new LogoutPersistor();
    routeGenerator.createLogoutRoute(logoutPersistor);
  });

  it('should be able to create a user', async () => {
    console.debug('here');
    const res = await request(app)
      .post('/v1/auth/signup')
      .send({ name: 'test1', email: 'test1@test.com' });
    expect(res.status).toBe(201);
    expect(res.body.message).toBe('User created');
  });

  it('should not be able to create a user', async () => {
    const res = await request(app)
      .post('/v1/auth/signup')
      .send({ name: 'test', email: 'test@test.com' });
    expect(res.status).toBe(409);
    expect(res.body.message).toBe('User already exists');
  });

  it('should be able to create a user', async () => {
    const res = await request(app)
      .post('/v1/auth/signup')
      .send({ name: 'ram', email: 'ram@test.com' });
    expect(res.status).toBe(201);
    expect(res.body.message).toBe('User created');
  });

  it('should not be able to login', async () => {
    const res = await request(app)
      .post('/v1/auth/login')
      .send({ email: 'john@test.com', password: 'wrong...' });
    expect(res.status).toBe(409);
    expect(res.body.message).toBe('Password or email incorrect');
  });

  it('should be able to login', async () => {
    const res = await request(app)
      .post('/v1/auth/login')
      .send({ email: 'test@test.com', password: 'test' });
    const cookies = res.headers['set-cookie'];

    console.debug('cookies', cookies);

    for (const cookie of cookies) {
      const [cookieName, cookieValue] = cookie.split('=');
      if (cookieName === 'x-access-token') {
        expect(cookieValue).toBeTruthy();
      }
      if (cookieName === 'x-refresh-token') {
        expect(cookieValue).toBeTruthy();
      }
    }

    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Logged in successfully!!');
  });

  it('should revoke token', async () => {
    const res = await request(app)
      .post('/v1/auth/logout')
      .set('Cookie', [
        'x-access-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJpYXQiOjE2NjUyNzYyMzgsImV4cCI6MTY2NTI3NjIzOH0.8QrJ4QKjzKdO0Z9nVJt5QD6vW1d5PwZw2OuZ6ZxYyI8',
        'x-refresh-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJpYXQiOjE2NjUyNzYyMzgsImV4cCI6MTY2NTI3NjIzOH0.8QrJ4QKjzKdO0Z9nVJt5QD6vW1d5PwZw2OuZ6ZxYyI8',
      ]);
    expect(res.status).toBe(200);
    expect(res.body.message).toBe('Logged out successfully!!');
  });
});
