import { Application as ExpressApplication } from 'express';

export interface ISignUpPersistor {
  errors: {
    USER_ALREADY_EXISTS_MESSAGE?: string;
  };
  doesUserExists: (body: any) => Promise<boolean>;
  saveUser: (body: any) => Promise<void>;
}

interface IRouteGenerator {
  createSignUpRoute: (signUpPersistor: ISignUpPersistor) => ExpressApplication;
  createLoginRoute: () => void;
  createLogoutRoute: () => void;
}

const BASE_PATH = '/v1/auth';

export class RouteGenerator implements IRouteGenerator {
  constructor(private app: ExpressApplication) {
    //
  }

  createSignUpRoute(signUpPersistor: ISignUpPersistor) {
    return this.app.post(`${BASE_PATH}/signup`, async (req, res) => {
      const isUserExists = await signUpPersistor.doesUserExists(req.body);
      if (isUserExists) {
        res.status(409).json({
          message:
            signUpPersistor.errors.USER_ALREADY_EXISTS_MESSAGE ??
            'User already exists',
        });
        return;
      }
      await signUpPersistor.saveUser(req.body);

      res.status(201).json({
        message: 'User created',
      });
    });
  }

  createLoginRoute() {
    throw new Error('not implemented yet');
  }
  createLogoutRoute() {
    throw new Error('not implemented yet');
  }
}
