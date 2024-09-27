import { config as dConfig } from 'dotenv';

dConfig({
  path: '.env',
});

import {
  Application as ExpressApplication,
  Request,
  Response,
  NextFunction,
} from 'express';
import {
  comparePassword,
  extractDeviceIdentifier,
  generateTokens,
  hashPassword,
  setCookies,
  verifyToken,
} from '../utils';
import { SessionManager } from '../session-storage/session';

export type TConfig = {
  /**
   * Base path for all routes for e.g. `/v1/auth`
   */
  BASE_PATH: string;

  /**
   * Number of rounds for password hashing
   */
  SALT_ROUNDS: number;

  /**
   * Secret used for generating access and refresh tokens
   */
  TOKEN_SECRET: string;

  /**
   * Age of access tokens when token is signed in seconds
   */
  ACCESS_TOKEN_AGE: number;

  /**
   * Age of refresh tokens when token is signed in seconds
   */
  REFRESH_TOKEN_AGE: number;

  /**
   * Age of access token for email verification in seconds
   */
  EMAIL_VERIFICATION_TOKEN_AGE: number;
};

export interface ISignUpPersistor<P> {
  errors: {
    /**
     * Message that will be returned if user already exists
     */
    USER_ALREADY_EXISTS_MESSAGE?: string;
  };

  /**
   * Returns true if user already exists in the storage
   */
  doesUserExists: (
    body: P extends { email: string } ? P : never
  ) => Promise<boolean>;

  /**
   * Saves user in the storage after hashing password
   */
  saveUser: (
    body: P extends { email: string } ? P : never,
    hashedPassword: string
  ) => Promise<void>;
}

export interface ILoginPersistor<Q> {
  errors: {
    /**
     * Message that will be returned if password or email is incorrect
     */
    PASSWORD_OR_EMAIL_INCORRECT?: string;
  };

  /**
   * Returns the payload object that is signed in the access and refresh tokens
   */
  getTokenPayload: (email: string) => Promise<Omit<Q, 'password'>>;

  /**
   * Returns the user data from the storage that must contain `email`
   */
  getUserByEmail: (
    email: string
  ) => Promise<Q extends { email: string; password: string } ? Q : null>;
}

export interface ILogoutPersistor {
  /**
   * Revokes access and refresh tokens
   */
  revokeTokens: (token: {
    refreshToken: string;
    accessToken: string;
  }) => Promise<boolean>;
}

export interface IRefreshPersistor<R> {
  errors: {
    /**
     * Message that will be returned if refresh token is invalid
     */
    INVALID_REFRESH_TOKEN?: string;
  };

  /**
   * Returns true if token is eligible for refresh. The token might be revoked.
   */
  isTokenEligibleForRefresh: (token: string) => Promise<boolean>;

  /**
   * Returns the payload object that is signed in the access and refresh tokens
   */
  getTokenPayload: (
    email: string
  ) => Promise<R extends { email: string } ? R : null>;
}

/**
 * In order to reset a password, a user must be logged in.
 * Access token, old password and new password are sent in the request.
 */
export interface IResetPasswordPersistor {
  /**
   * Returns the user's old password hash from the storage
   */
  getOldPasswordHash: (email: string) => Promise<string>;

  /**
   * Saves the new password hash in the storage
   */
  saveHashedPassword: (email: string, hashedPassword: string) => Promise<void>;
}

export interface IMeRoutePersistor<S> {
  /**
   * Returns the user data from the storage that must contain `email`
   */
  getMeByEmail: (
    email: string
  ) => Promise<S extends { email: string } ? S : null>;
}

export interface IVerifyEmailPersistor {
  errors: {
    EMAIL_NOT_ELIGIBLE_FOR_VERIFICATION?: string;
  };

  isEmailEligibleForVerification: (email: string) => Promise<boolean>;

  sendVerificationEmail: (input: {
    email: string;
    verificationPath: string;
  }) => Promise<void>;
}

interface IRouteGenerator<P, Q, R, S> {
  createSignUpRoute: (
    signUpPersistor: ISignUpPersistor<P>
  ) => ExpressApplication;
  createLoginRoute: (loginPersistor: ILoginPersistor<Q>) => ExpressApplication;
  createLogoutRoute: (logoutPersistor: ILogoutPersistor) => ExpressApplication;
  createRefreshRoute: (
    refreshPersistor: IRefreshPersistor<R>
  ) => ExpressApplication;
  createResetPasswordRoute: (
    resetPasswordPersistor: IResetPasswordPersistor
  ) => ExpressApplication;
  createMeRoute: (meRoutePersistor: IMeRoutePersistor<S>) => ExpressApplication;
  createVerifyEmailRoute: (
    verifyEmailPersistor: IVerifyEmailPersistor
  ) => ExpressApplication;
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

const config: TConfig = {
  BASE_PATH: '/v1/auth',
  SALT_ROUNDS: Number(process.env['SALT_ROUNDS']) || 10,
  TOKEN_SECRET: process.env['TOKEN_SECRET'] || '',
  ACCESS_TOKEN_AGE: Number(process.env['ACCESS_TOKEN_AGE']) || 60,
  REFRESH_TOKEN_AGE: Number(process.env['REFRESH_TOKEN_AGE']) || 3600,
  EMAIL_VERIFICATION_TOKEN_AGE:
    Number(process.env['EMAIL_VERIFICATION_TOKEN_AGE']) || 60,
};

export class RouteGenerator<P, Q, R, S>
  implements IRouteGenerator<P, Q, R, S>, IRouteMiddlewares
{
  constructor(
    private app: ExpressApplication,
    private sessionManager: SessionManager
  ) {}

  createSignUpRoute(signUpPersistor: ISignUpPersistor<P>) {
    return this.app.post(`${config.BASE_PATH}/signup`, async (req, res) => {
      const isUserExists = await signUpPersistor.doesUserExists(req.body);
      if (isUserExists) {
        res.status(409).json({
          message:
            signUpPersistor.errors.USER_ALREADY_EXISTS_MESSAGE ??
            'User already exists',
        });
        return;
      }

      // !FIXME: password validations can be done here
      const [_, hashedPasswordStr] = await hashPassword(
        req.body.password,
        config.SALT_ROUNDS
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

  createLoginRoute(logingPersistor: ILoginPersistor<Q>) {
    return this.app.post(`${config.BASE_PATH}/login`, async (req, res) => {
      const user = await logingPersistor.getUserByEmail(req.body.email);

      if (!user) {
        res.status(409).json({
          message: logingPersistor.errors.PASSWORD_OR_EMAIL_INCORRECT ?? '',
        });
        return;
      }

      const [_, isPasswordMatch] = await comparePassword({
        password: req.body.password,
        hashedPassword: user.password,
      });

      if (!isPasswordMatch) {
        res.status(409).json({
          message: logingPersistor.errors.PASSWORD_OR_EMAIL_INCORRECT ?? '',
        });
        return;
      }

      const payload = await logingPersistor.getTokenPayload(req.body.email);

      const tokens = generateTokens(payload, {
        tokenSecret: config.TOKEN_SECRET,
        ACCESS_TOKEN_AGE: config.ACCESS_TOKEN_AGE,
        REFRESH_TOKEN_AGE: config.REFRESH_TOKEN_AGE,
      });

      const deviceInfo = extractDeviceIdentifier(req);

      this.sessionManager.storeSession(tokens.refreshToken, deviceInfo);

      setCookies({
        res,
        cookieData: [
          {
            cookieName: 'x-access-token',
            cookieValue: tokens.accessToken,
            maxAge: config.ACCESS_TOKEN_AGE * 1000,
          },
          {
            cookieName: 'x-refresh-token',
            cookieValue: tokens.refreshToken,
            maxAge: config.REFRESH_TOKEN_AGE * 1000,
          },
        ],
      });

      res.status(200).json({
        message: 'Logged in successfully!!',
      });
    });
  }

  createLogoutRoute(logoutPersistor: ILogoutPersistor) {
    return this.app.post(
      `${config.BASE_PATH}/logout`,
      this.validateAccessToken,
      this.validateRefreshToken,
      async (req, res) => {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-expect-error
        const accessToken = req['accessToken'];
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-expect-error
        const refreshToken = req['refreshToken'];

        const isRevoked = await logoutPersistor.revokeTokens({
          refreshToken,
          accessToken,
        });

        if (!isRevoked) {
          res.status(500).json({
            message: 'Failed to revoke the tokens',
          });
          return;
        }

        setCookies({
          res,
          cookieData: [
            {
              cookieName: 'x-access-token',
              cookieValue: '',
              maxAge: config.ACCESS_TOKEN_AGE * 1000,
            },
            {
              cookieName: 'x-refresh-token',
              cookieValue: '',
              maxAge: config.REFRESH_TOKEN_AGE * 1000,
            },
          ],
        });

        res.status(200).json({
          message: 'Logged out successfully!!',
        });
      }
    );
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
        message: 'Access token not found in the cookie',
      });
      return;
    }

    // check if token is valid or not
    const isTokenValid = verifyToken({
      token,
      tokenSecret: config.TOKEN_SECRET,
    });
    if (!isTokenValid) {
      res.status(400).json({
        message: 'Access Token is invalid',
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
        message: 'Refresh Token not found in the cookie',
      });
      return;
    }

    // check if token is valid or not
    const isTokenValid = verifyToken({
      token,
      tokenSecret: config.TOKEN_SECRET,
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

  createRefreshRoute(refreshPersistor: IRefreshPersistor<R>) {
    return this.app.post(
      `${config.BASE_PATH}/refresh`,
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

        const isEligibleForRefresh =
          await refreshPersistor.isTokenEligibleForRefresh(refreshToken);

        if (!isEligibleForRefresh) {
          res.status(400).json({
            message:
              refreshPersistor.errors?.INVALID_REFRESH_TOKEN ||
              'Refresh token is not eligible for refresh. It might be revoked.',
          });
          return;
        }

        // validate the refreshToken
        const decodedToken = await verifyToken({
          token: refreshToken,
          tokenSecret: config.TOKEN_SECRET,
        });

        if (!decodedToken) {
          res.status(400).json({
            message:
              refreshPersistor.errors?.INVALID_REFRESH_TOKEN ||
              'Refresh token could not be verified',
          });
          return;
        }

        /**
         * Generate new access token and refresh token and set on the cookie
         */
        if (!(typeof decodedToken === 'object' && 'email' in decodedToken)) {
          res.status(400).json({
            message:
              refreshPersistor.errors?.INVALID_REFRESH_TOKEN ||
              'Decoded token is not an object with email property',
          });
          return;
        }
        const payload = await refreshPersistor.getTokenPayload(
          decodedToken['email']
        );

        const tokens = generateTokens(payload, {
          tokenSecret: config.TOKEN_SECRET,
          ACCESS_TOKEN_AGE: config.ACCESS_TOKEN_AGE,
          REFRESH_TOKEN_AGE: config.REFRESH_TOKEN_AGE,
        });

        setCookies({
          res,
          cookieData: [
            {
              cookieName: 'x-access-token',
              cookieValue: tokens.accessToken,
              maxAge: config.ACCESS_TOKEN_AGE * 1000,
            },
            {
              cookieName: 'x-refresh-token',
              cookieValue: tokens.refreshToken,
              maxAge: config.REFRESH_TOKEN_AGE * 1000,
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
      `${config.BASE_PATH}/reset`,
      this.validateAccessToken,
      async (req, res) => {
        // body has oldPassword and newPassword
        const oldPassword = req.body.oldPassword;
        const newPassword = req.body.newPassword;

        /**
         * Get the email from the access token
         */
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-expect-error
        const accessToken = req['accessToken'];
        const decodedToken = await verifyToken({
          token: accessToken,
          tokenSecret: config.TOKEN_SECRET,
        });

        if (!decodedToken) {
          res.status(500).json({
            message: 'Access token could not be verified',
          });
          return;
        }

        /**
         * Generate new access token and refresh token and set on the cookie
         */
        if (!(typeof decodedToken === 'object' && 'email' in decodedToken)) {
          res.status(400).json({
            message: 'Decoded token is not an object with email property',
          });
          return;
        }

        const email = decodedToken['email'];

        const oldPasswordHash = await resetPasswordPersistor.getOldPasswordHash(
          email
        );

        // validating the old password
        const [, isOldPasswordValid] = await comparePassword({
          password: oldPassword,
          hashedPassword: oldPasswordHash,
        });
        if (!isOldPasswordValid) {
          res.status(403).json({
            message: 'Old password or username is not valid',
          });
          return;
        }

        // hash the new password and save in the database
        const [, hashedPassword] = await hashPassword(
          newPassword,
          config.SALT_ROUNDS
        );

        if (!hashedPassword) {
          res.status(500).json({
            message: 'Password could not be hashed',
          });
          return;
        }

        await resetPasswordPersistor.saveHashedPassword(email, hashedPassword);

        /**
         * logout
         */
        setCookies({
          res,
          cookieData: [
            {
              cookieName: 'x-access-token',
              cookieValue: '',
              maxAge: config.ACCESS_TOKEN_AGE * 1000,
            },
            {
              cookieName: 'x-refresh-token',
              cookieValue: '',
              maxAge: config.REFRESH_TOKEN_AGE * 1000,
            },
          ],
        });

        res.status(200).json({
          message: 'Password has been reset sucessfully! Please login again',
        });
      }
    );
  }

  createMeRoute(meRoutePersistor: IMeRoutePersistor<S>) {
    return this.app.get(
      `${config.BASE_PATH}/me`,
      this.validateAccessToken,
      async (req, res) => {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-expect-error
        const accessToken = req.accessToken;

        const decodedToken = verifyToken({
          token: accessToken,
          tokenSecret: config.TOKEN_SECRET,
        });

        if (!decodedToken) {
          res.status(500).json({
            message: 'Access token could not be verified',
          });
          return;
        }

        if (!(typeof decodedToken === 'object' && 'email' in decodedToken)) {
          res.status(400).json({
            message: 'Decoded token is not an object with email property',
          });
          return;
        }

        const email = decodedToken['email'];

        const meData = await meRoutePersistor.getMeByEmail(email);

        res.status(200).json({
          data: decodedToken,
          me: meData,
        });
      }
    );
  }

  createVerifyEmailRoute: (
    verifyEmailPersistor: IVerifyEmailPersistor
  ) => ExpressApplication = (verifyEmailPersistor) => {
    return this.app.post(
      `${config.BASE_PATH}/verify-email`,
      async (req, res, next) => {
        // verify that email is coming on the body
        const email = req.body.email;

        if (typeof email !== 'string') {
          res.status(400).json({
            message: 'Email invalid or not sent from the client',
          });
          return;
        }

        // validate if email is eligible for verification
        const isEligibleForVerification =
          await verifyEmailPersistor.isEmailEligibleForVerification(email);

        if (!isEligibleForVerification) {
          res.status(400).json({
            message:
              verifyEmailPersistor.errors.EMAIL_NOT_ELIGIBLE_FOR_VERIFICATION ||
              'Email is already verified',
          });
          return;
        }

        const path = this.generateEmailVerificationPath(email);

        await verifyEmailPersistor.sendVerificationEmail({
          email,
          verificationPath: path,
        });

        res.status(200).json({
          message: 'Verification email sent successfully',
        });
      }
    );
  };

  private generateEmailVerificationPath(email: string): string {
    const tokens = generateTokens(
      { email },
      {
        ACCESS_TOKEN_AGE: config.EMAIL_VERIFICATION_TOKEN_AGE,
        REFRESH_TOKEN_AGE: config.REFRESH_TOKEN_AGE,
        tokenSecret: config.TOKEN_SECRET,
      }
    );

    return `${config.BASE_PATH}/verify-email?token=${tokens.accessToken}`;
  }
}
