import request from 'supertest';
import express from 'express';

import { writeTestLogToFile } from '../util';

import { ISignUpPersistor, RouteGenerator } from './express-auth';

type TUser = {
  name: string;
  email: string;
};
const users: TUser[] = [
  {
    name: 'test',
    email: 'test@test.com',
  },
];

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

describe('expressAuth', () => {
  let app: express.Application;

  beforeAll(() => {
    app = express();
    app.use(express.json());
    const routeGenerator = new RouteGenerator(app);
    const signUpPersistor = new SignUpPersistor();
    routeGenerator.createSignUpRoute(signUpPersistor);
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
});
