import {
  Application as ExpressApplication,
  Request,
  Response,
  NextFunction,
} from 'express';

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

export interface ISignUpHandler {
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
    /**
     * Body of the request that contains `email`
     */
    body: any
  ) => Promise<boolean>;

  /**
   * Saves user in the storage after hashing password
   */
  saveUser: (
    /**
     * Body of the request that contains `email` and `name`
     */
    body: any,
    hashedPassword: string
  ) => Promise<void>;
}

export interface ILoginHandler {
  errors: {
    /**
     * Message that will be returned if password or email is incorrect
     */
    PASSWORD_OR_EMAIL_INCORRECT?: string;
  };

  /**
   * Decide if user can login or not
   * For e.g. in case of email not verified do not allow
   */
  canLogin: (email: string) => Promise<boolean>;

  /**
   * Returns the payload object that is signed in the access and refresh tokens
   */
  getTokenPayload: (email: string) => Promise<any>;

  /**
   * Returns the user data from the storage that must contain `email` and `password`
   */
  getUserByEmail: (email: string) => Promise<any>;
}

export interface ILogoutHandler {
  /**
   * Just to have a non empty interface
   * You should always return true
   */
  shouldLogout: () => Promise<boolean>;
}

export interface IRefreshHandler {
  errors: {
    /**
     * Message that will be returned if refresh token is invalid
     */
    INVALID_REFRESH_TOKEN?: string;
  };

  /**
   * Returns the payload object that must contains `email` that is signed in the access and refresh tokens
   */
  getTokenPayload: (email: string) => Promise<any>;
}

/**
 * In order to reset a password, a user must be logged in.
 * Access token, old password and new password are sent in the request.
 */
export interface IResetPasswordHandler {
  /**
   * Returns the user's old password hash from the storage
   */
  getOldPasswordHash: (email: string) => Promise<string>;

  /**
   * Saves the new password hash in the storage
   */
  saveHashedPassword: (email: string, hashedPassword: string) => Promise<void>;
}

export interface IMeRouteHandler {
  /**
   * Returns the user data from the storage that must contain `email`
   */
  getMeByEmail: (email: string) => Promise<any>;
}

export interface IVerifyEmailHandler {
  /**
   * Check the storage to see if user's email is already verified
   */
  isEmailAlreadyVerified: (email: string) => Promise<boolean>;

  /**
   * Check the storage if otp is valid
   */
  isOtpValid: (email: string, otp: string) => Promise<boolean>;
}

export interface ISendOtpHandler {
  /**
   * Check the storage to see if user exists or not
   */
  doesUserExists: (email: string) => Promise<boolean>;

  /**
   * Save the otp in the storage for verification
   */
  saveOtp: (
    email: string,
    otp: {
      code: string;
      generatedAt: number; // timestamp in seconds
    }
  ) => Promise<void>;
}

export interface IForgotPasswordHandler {
  /**
   * Check the storage to see if otp is valid
   */
  isOtpValid: (email: string, otp: string) => Promise<boolean>;

  /**
   * Save the new password in the storage
   */
  saveNewPassword: (email: string, password: string) => Promise<void>;
}

export interface IRouteGenerator {
  createSignUpRoute: (signUpPersistor: ISignUpHandler) => ExpressApplication;
  createLoginRoute: (loginPersistor: ILoginHandler) => ExpressApplication;
  createLogoutRoute: (logoutPersistor: ILogoutHandler) => ExpressApplication;
  createRefreshRoute: (refreshPersistor: IRefreshHandler) => ExpressApplication;
  createResetPasswordRoute: (
    resetPasswordPersistor: IResetPasswordHandler
  ) => ExpressApplication;
  createMeRoute: (meRoutePersistor: IMeRouteHandler) => ExpressApplication;
  createVerifyEmailRoute: (
    verifyEmailPersistor: IVerifyEmailHandler
  ) => ExpressApplication;
  createSendOtpRoute: (sendOtpPersistor: ISendOtpHandler) => ExpressApplication;
  createForgotPasswordRoute: (
    forgotPasswordHandler: IForgotPasswordHandler
  ) => ExpressApplication;
}

export interface IRouteMiddlewares {
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
  validateSessionDeviceInfo: (
    req: Request,
    res: Response,
    next: NextFunction
  ) => void;
}
