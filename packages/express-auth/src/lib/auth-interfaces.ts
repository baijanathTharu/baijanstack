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
   * Age of otp in seconds
   */
  OTP_AGE: number;

  /**
   * OTP SECRET
   */
  OTP_SECRET: string;

  /**
   * If you want to generate the same otp all the time,
   * may be for testing purposes.
   * Provide the 6 digits otp here.
   */
  TEST_OTP?: string;
};

export interface ISignUpHandler {
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
   * Updates `is_email_verified` to true if otp is valid
   */
  updateIsEmailVerifiedField: (email: string) => Promise<void>;
}

export interface ISendOtpHandler {
  /**
   * Check the storage to see if user exists or not
   */
  doesUserExists: (email: string) => Promise<boolean>;
}

export interface IForgotPasswordHandler {
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
  /**
   * @deprecated
   */
  validateAccessToken?: (
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

export enum AuthProvider {
  GOOGLE = 'google',
}

export interface IOAuthHandler {
  /**
   * Creates or updates user in the storage
   * based on the email provided by the OAuth provider.
   * Returns true if user was created or updated.
   * Returns false if user already exists and was not updated.
   */
  createOrUpdateUser: (payload: {
    email: string;
    googleId: string;
    provider: AuthProvider;
    displayName?: string;
  }) => Promise<boolean>;

  /**
   * Returns the payload object that is signed in the access and refresh tokens
   */
  getTokenPayload: (email: string) => Promise<any>;
}

export interface IOAuthGenerator {
  createOAuthRoute: (provider: AuthProvider) => ExpressApplication;
}

export type TGoogleAuthConfig = {
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GOOGLE_FAILURE_REDIRECT_URI: string;
  GOOGLE_SUCCESS_REDIRECT_URI: string;
};
export type TGoogleProfile = {
  id: string;
  displayName: string;
  email: string;
};
