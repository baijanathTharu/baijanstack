import { Application as ExpressApplication } from 'express';
import { generateTokens, setCookies } from '../utils';

export interface ISignUpPersistor {
  errors: {
    USER_ALREADY_EXISTS_MESSAGE?: string;
  };
  doesUserExists: (body: any) => Promise<boolean>;
  saveUser: (body: any) => Promise<void>;
}

export interface ILoginPersistor {
  errors: {
    PASSWORD_OR_EMAIL_INCORRECT?: string;
  };
  login: () => Promise<void>;
  doesUserExists: (body: any) => Promise<boolean>;
  doesPasswordMatch: (body: any) => Promise<boolean>;
  getTokenInput: (body: any) => Promise<string[]>;
}

interface IRouteGenerator {
  createSignUpRoute: (signUpPersistor: ISignUpPersistor) => ExpressApplication;
  createLoginRoute: (loginPersistor: ILoginPersistor) => void;
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

  createLoginRoute(logingPersistor: ILoginPersistor) {
    return this.app.post(`${BASE_PATH}/login`, async (req, res) => {
      const isUserExists = await logingPersistor.doesUserExists(req.body);
      if (!isUserExists) {
        res.status(409).json({
          message: logingPersistor.errors.PASSWORD_OR_EMAIL_INCORRECT ?? '',
        });
        return;
      }

      const isPasswordMatch = await logingPersistor.doesPasswordMatch(req.body);
      if (!isPasswordMatch) {
        res.status(409).json({
          message: logingPersistor.errors.PASSWORD_OR_EMAIL_INCORRECT ?? '',
        });
        return;
      }

      const keys = await logingPersistor.getTokenInput(req.body);
      const tokenInput: Record<string, string> = {};
      for (const key of req.body) {
        if (keys.includes(key)) {
          tokenInput[key] = req.body[key];
        }
      }

      const tokens = generateTokens(JSON.stringify(tokenInput));

      setCookies({
        res,
        cookieData: [
          {
            cookieName: 'x-access-token',
            cookieValue: tokens.accessToken,
            maxAge: Number(process.env['ACCESS_TOKEN_AGE']),
          },
          {
            cookieName: 'x-refresh-token',
            cookieValue: tokens.refreshToken,
            maxAge: Number(process.env['REFRESH_TOKEN_AGE']),
          },
        ],
      });

      await logingPersistor.login();

      res.status(200).json({
        message: 'Logged in successfully',
      });
    });
  }
  createLogoutRoute() {
    throw new Error('not implemented yet');
  }
}
