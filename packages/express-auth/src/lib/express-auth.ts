import {
  Application as ExpressApplication,
  Request,
  Response,
  NextFunction,
} from 'express';
import {
  comparePassword,
  generateTokens,
  hashPassword,
  setCookies,
  verifyToken,
} from '../utils';

export type TConfig = {
  SALT_ROUNDS: number;
  TOKEN_SECRET: string;
  ACCESS_TOKEN_AGE: string;
  REFRESH_TOKEN_AGE: string;
  ACCESS_TOKEN_COOKIE_MAX_AGE: number; // in seconds
  REFRESH_TOKEN_COOKIE_MAX_AGE: number; // in seconds
};

export interface ISignUpPersistor {
  errors: {
    USER_ALREADY_EXISTS_MESSAGE?: string;
  };
  // body should contain password
  doesUserExists: (body: any) => Promise<boolean>;
  // body should contain password
  saveUser: (body: any, hashedPassword: string) => Promise<void>;
}

export interface ILoginPersistor {
  errors: {
    PASSWORD_OR_EMAIL_INCORRECT?: string;
  };
  login: () => Promise<void>;
  doesUserExists: (body: any) => Promise<boolean>;
  doesPasswordMatch: (body: any) => Promise<boolean>;
  // contains email in body
  getTokenPayload: (body: any) => Promise<any>;
}

export interface ILogoutPersistor {
  // TODO: need to implement this
  revokeTokens: () => Promise<boolean>;
}

export interface IRefreshPersistor {
  errors: {
    INVALID_REFRESH_TOKEN?: string;
  };
  isTokenEligibleForRefresh: (token: string) => Promise<boolean>;
  refresh: (token: string) => Promise<void>;
  getTokenPayload: () => Promise<any>;
}

/**
 * In order to reset a password, a user must be logged in.
 * Access token, old password and new password are sent in the request.
 */
export interface IResetPasswordPersistor {
  saveHashedPassword: (hashedPassword: string) => Promise<void>;
  getOldPasswordHash: () => Promise<string>;
}

export interface IMeRoutePersistor {
  getMeByUserId: () => Promise<any>;
}

interface IRouteGenerator {
  createSignUpRoute: (signUpPersistor: ISignUpPersistor) => ExpressApplication;
  createLoginRoute: (loginPersistor: ILoginPersistor) => ExpressApplication;
  createLogoutRoute: (logoutPersistor: ILogoutPersistor) => ExpressApplication;
  createRefreshRoute: (
    refreshPersistor: IRefreshPersistor
  ) => ExpressApplication;
  createResetPasswordRoute: (
    resetPasswordPersistor: IResetPasswordPersistor
  ) => ExpressApplication;
  createMeRoute: (meRoutePersistor: IMeRoutePersistor) => ExpressApplication;
}

interface IRouteMiddlewares {
  validateAccessToken: (
    req: Request,
    res: Response,
    next: NextFunction
  ) => void;
  validateRefreshToken: (
    req: Request,
    res: Response,
    next: NextFunction
  ) => void;
}

const BASE_PATH = '/v1/auth';

export class RouteGenerator implements IRouteGenerator, IRouteMiddlewares {
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

      const [_, hashedPasswordStr] = await hashPassword(
        req.body.password,
        this.config.SALT_ROUNDS
      );

      if (!hashedPasswordStr) {
        res.status(500).json({
          message: 'Failed to hash the password',
        });
        return;
      }

      await signUpPersistor.saveUser(req.body, hashedPasswordStr);

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

      const payload = await logingPersistor.getTokenPayload(req.body);

      const tokens = generateTokens(payload, {
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

  validateAccessToken(req: Request, res: Response, next: NextFunction) {
    const cookies = req.cookies;
    if (!cookies) {
      res.status(400).json({
        message: 'Cookies are not sent from the client',
      });
      return;
    }
    const token = cookies['x-access-token'];
    if (!token) {
      res.status(400).json({
        message: 'Token not found in the cookie',
      });
      return;
    }

    // check if token is valid or not
    const isTokenValid = verifyToken({
      token,
      tokenSecret: this.config.TOKEN_SECRET,
    });
    if (!isTokenValid) {
      res.status(400).json({
        message: 'Token is invalid',
      });
      return;
    }

    // token is valid, call the next middleware
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    req['accessToken'] = token;
    next();
  }

  validateRefreshToken(req: Request, res: Response, next: NextFunction) {
    const cookies = req.cookies;
    if (!cookies) {
      res.status(400).json({
        message: 'Cookies are not sent from the client',
      });
      return;
    }
    const token = cookies['x-refresh-token'];
    if (!token) {
      res.status(400).json({
        message: 'Token not found in the cookie',
      });
      return;
    }

    // check if token is valid or not
    const isTokenValid = verifyToken({
      token,
      tokenSecret: this.config.TOKEN_SECRET,
    });
    if (!isTokenValid) {
      res.status(400).json({
        message: 'Token is invalid',
      });
      return;
    }

    // token is valid, call the next middleware
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    req['refreshToken'] = token;
    next();
  }

  createRefreshRoute(refreshPersistor: IRefreshPersistor) {
    return this.app.post(
      `${BASE_PATH}/refresh`,
      this.validateRefreshToken,
      async (req, res) => {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-expect-error
        const refreshToken = req['refreshToken'] as string;

        const isEligible = await refreshPersistor.isTokenEligibleForRefresh(
          refreshToken
        );

        if (!isEligible) {
          res.status(400).json({
            message:
              refreshPersistor.errors?.INVALID_REFRESH_TOKEN ||
              'Refresh token is not eligible for refresh. It might be revoked.',
          });
          return;
        }

        await refreshPersistor.isTokenEligibleForRefresh(refreshToken);
        await refreshPersistor.refresh(refreshToken);

        /**
         * Generate new access token and refresh token and set on the cookie
         */
        const payload = await refreshPersistor.getTokenPayload();

        const tokens = generateTokens(payload, {
          tokenSecret: this.config.TOKEN_SECRET,
          ACCESS_TOKEN_AGE: this.config.ACCESS_TOKEN_AGE,
          REFRESH_TOKEN_AGE: this.config.REFRESH_TOKEN_AGE,
        });

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
          message: 'Refreshed token successfully!!',
        });
      }
    );
  }

  createResetPasswordRoute(resetPasswordPersistor: IResetPasswordPersistor) {
    return this.app.post(
      `${BASE_PATH}/reset`,
      this.validateAccessToken,
      async (req, res) => {
        // body has oldPassword and newPassword
        const oldPassword = req.body.oldPassword;
        const newPassword = req.body.newPassword;

        const oldPasswordHash =
          await resetPasswordPersistor.getOldPasswordHash();

        // validating the old password
        const [, isOldPasswordValid] = await comparePassword({
          password: oldPassword,
          hashedPassword: oldPasswordHash,
        });
        if (!isOldPasswordValid) {
          res.status(403).json({
            message: 'Old password or username not valid',
          });
          return;
        }

        // hash the new password and save in the database
        const [, hashedPassword] = await hashPassword(
          newPassword,
          this.config.SALT_ROUNDS
        );

        if (!hashedPassword) {
          res.status(500).json({
            message: 'Password could not be hased',
          });
          return;
        }

        await resetPasswordPersistor.saveHashedPassword(hashedPassword);
      }
    );
  }

  createMeRoute(meRoutePersistor: IMeRoutePersistor) {
    return this.app.get(
      `${BASE_PATH}/me`,
      this.validateAccessToken,
      async (req, res) => {
        await meRoutePersistor.getMeByUserId();

        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-expect-error
        const accessToken = req.accessToken;

        const decodedToken = verifyToken({
          token: accessToken,
          tokenSecret: this.config.TOKEN_SECRET,
        });

        res.status(200).json({
          data: decodedToken,
        });
      }
    );
  }
}
