import { Application as ExpressApplication } from 'express';
import { generateTokens, setCookies } from '../utils';

export type TConfig = {
  SALT_ROUNDS: string;
  TOKEN_SECRET: string;
  ACCESS_TOKEN_AGE: string;
  REFRESH_TOKEN_AGE: string;
  ACCESS_TOKEN_COOKIE_MAX_AGE: number; // in milliseconds
  REFRESH_TOKEN_COOKIE_MAX_AGE: number; // in milliseconds
};

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
  tokenKeysFromBody: (body: any) => Promise<string[]>;
}

export interface ILogoutPersistor {
  revokeTokens: () => Promise<boolean>;
}

interface IRouteGenerator {
  createSignUpRoute: (signUpPersistor: ISignUpPersistor) => ExpressApplication;
  createLoginRoute: (loginPersistor: ILoginPersistor) => ExpressApplication;
  createLogoutRoute: (logoutPersistor: ILogoutPersistor) => ExpressApplication;
}

const BASE_PATH = '/v1/auth';

export class RouteGenerator implements IRouteGenerator {
  private config: TConfig;

  constructor(private app: ExpressApplication, config: TConfig) {
    this.config = config;
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

      // !FIXME: password hashing & validations
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

      const keys = await logingPersistor.tokenKeysFromBody(req.body);
      const tokenInput: Record<string, string> = {};
      for (const key in req.body) {
        if (keys.includes(key)) {
          tokenInput[key] = req.body[key];
        }
      }

      const tokens = generateTokens(tokenInput, {
        tokenSecret: this.config.TOKEN_SECRET,
        ACCESS_TOKEN_AGE: this.config.ACCESS_TOKEN_AGE,
        REFRESH_TOKEN_AGE: this.config.REFRESH_TOKEN_AGE,
      });

      await logingPersistor.login();

      setCookies({
        res,
        cookieData: [
          {
            cookieName: 'x-access-token',
            cookieValue: tokens.accessToken,
            maxAge: this.config.ACCESS_TOKEN_COOKIE_MAX_AGE,
          },
          {
            cookieName: 'x-refresh-token',
            cookieValue: tokens.refreshToken,
            maxAge: this.config.REFRESH_TOKEN_COOKIE_MAX_AGE,
          },
        ],
      });

      res.status(200).json({
        message: 'Logged in successfully!!',
      });
    });
  }

  createLogoutRoute(logoutPersistor: ILogoutPersistor) {
    return this.app.post(`${BASE_PATH}/logout`, async (req, res) => {
      // !FIXME: get token and validate them

      const cookies = req.headers.cookie;
      console.debug('cookies received', cookies);

      const isRevoked = await logoutPersistor.revokeTokens();

      if (!isRevoked) {
        res.status(400).json({
          message: 'Failed to revoke token',
        });
      }

      res.status(200).json({
        message: 'Logged out successfully!!',
      });
    });
  }
}
