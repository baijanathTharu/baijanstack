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
import {
  ILoginHandler,
  ILogoutHandler,
  IMeRouteHandler,
  IRefreshHandler,
  IResetPasswordHandler,
  IRouteGenerator,
  IRouteMiddlewares,
  ISignUpHandler,
  IVerifyEmailHandler,
  IForgotPasswordHandler,
  TConfig,
  ISendOtpHandler,
  IValidation,
} from './auth-interfaces';
import { INotifyService, SessionManager } from './session-interfaces';
import { MemoryStorage } from './session-storage';
import {
  DeviceValidationResponseCodes,
  ForgotPasswordResponseCodes,
  LoginResponseCodes,
  LogoutResponseCodes,
  MeResponseCodes,
  RefreshResponseCodes,
  ResetPasswordResponseCodes,
  SendOtpResponseCodes,
  SignUpResponseCodes,
  ValidateTokenResponseCodes,
  VerifyEmailResponseCodes,
} from './response-codes';
import { IOTPService, OTPService } from './otp';
import { promises } from 'dns';

export class RouteGenerator implements IRouteGenerator, IRouteMiddlewares {
  private otpService: IOTPService;
  constructor(
    private app: ExpressApplication,
    private notifyService: INotifyService,
    private config: TConfig,
    private sessionManager?: SessionManager
  ) {
    this.otpService = OTPService.getInstance({ step: this.config.OTP_AGE });
    if (!this.sessionManager) {
      /**
       * Use the memory storage by default
       */
      this.sessionManager = new SessionManager(new MemoryStorage());
    }
  }

  createSignUpRoute: (signUpHandler: ISignUpHandler) => ExpressApplication = (
    signUpHandler
  ) => {
    return this.app.post(
      `${this.config.BASE_PATH}/signup`,
      async (req, res) => {
        try {
          /**
           * if body does not have email or password, return error
           */
          if (!req.body.email) {
            res.status(400).json({
              message: 'Email is required',
              code: SignUpResponseCodes.VALIDATION_FAILED,
            });
            return;
          }

          if (!req.body.password) {
            res.status(400).json({
              message: 'Password is required',
              code: SignUpResponseCodes.VALIDATION_FAILED,
            });
            return;
          }

          const isUserExists = await signUpHandler.doesUserExists(req.body);
          if (isUserExists) {
            res.status(409).json({
              message: 'User already exists',
              code: SignUpResponseCodes.USER_ALREADY_EXISTS,
            });
            return;
          }

          const [_, hashedPasswordStr] = await hashPassword(
            req.body.password,
            this.config.SALT_ROUNDS
          );

          if (!hashedPasswordStr) {
            res.status(500).json({
              message: 'Failed to hash the password',
              code: SignUpResponseCodes.PASSWORD_HASH_ERROR,
            });
            return;
          }

          await signUpHandler.saveUser(req.body, hashedPasswordStr);

          res.status(201).json({
            message: 'User created',
            code: SignUpResponseCodes.USER_CREATED,
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({
            message: 'Internal server error',
            code: SignUpResponseCodes.INTERNAL_SERVER_ERROR,
          });
        }
      }
    );
  };

  createLoginRoute: (loginHandler: ILoginHandler) => ExpressApplication = (
    loginHandler
  ) => {
    return this.app.post(`${this.config.BASE_PATH}/login`, async (req, res) => {
      try {
        if (!req.body.email) {
          res.status(400).json({
            message: 'Email is required',
            code: LoginResponseCodes.VALIDATION_FAILED,
          });
          return;
        }

        if (!req.body.password) {
          res.status(400).json({
            message: 'Password is required',
            code: LoginResponseCodes.VALIDATION_FAILED,
          });
          return;
        }

        const user = await loginHandler.getUserByEmail(req.body.email);

        if (!user) {
          res.status(409).json({
            message: 'Password or email incorrect',
            code: LoginResponseCodes.PASSWORD_OR_EMAIL_INCORRECT,
          });
          return;
        }

        const [_, isPasswordMatch] = await comparePassword({
          password: req.body.password,
          hashedPassword: user.password,
        });

        if (!isPasswordMatch) {
          res.status(409).json({
            message: 'Password or email incorrect',
            code: LoginResponseCodes.PASSWORD_OR_EMAIL_INCORRECT,
          });
          return;
        }

        if (!user.is_email_verified) {
          res.status(400).json({
            message:
              'You are not allowed to login because your email is not verified!',
            code: LoginResponseCodes.EMAIL_NOT_VERIFIED,
          });
          return;
        }

        const payload = await loginHandler.getTokenPayload(req.body.email);

        const tokens = generateTokens(payload, {
          tokenSecret: this.config?.TOKEN_SECRET ?? '',
          ACCESS_TOKEN_AGE: this.config.ACCESS_TOKEN_AGE,
          REFRESH_TOKEN_AGE: this.config.REFRESH_TOKEN_AGE,
        });

        const deviceInfo = extractDeviceIdentifier(req);

        if (this.sessionManager) {
          this.sessionManager.storeSession(
            tokens.refreshToken,
            req.body.email,
            deviceInfo,
            this.config.REFRESH_TOKEN_AGE * 1000
          );
        }

        setCookies({
          res,
          cookieData: [
            {
              cookieName: 'x-access-token',
              cookieValue: tokens.accessToken,
              maxAge: this.config.ACCESS_TOKEN_AGE * 1000,
            },
            {
              cookieName: 'x-refresh-token',
              cookieValue: tokens.refreshToken,
              maxAge: this.config.REFRESH_TOKEN_AGE * 1000,
            },
          ],
        });

        res.status(200).json({
          message: 'Logged in successfully!!',
          code: LoginResponseCodes.LOGIN_SUCCESS,
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({
          message: 'Internal server error',
          code: LoginResponseCodes.INTERNAL_SERVER_ERROR,
        });
      }
    });
  };

  createLogoutRoute: (logoutHanlder: ILogoutHandler) => ExpressApplication =
    () => {
      return this.app.post(
        `${this.config.BASE_PATH}/logout`,
        this.validateAccessToken,
        this.validateRefreshToken,

        async (req, res) => {
          try {
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-expect-error
            const refreshToken = req['refreshToken'];

            setCookies({
              res,
              cookieData: [
                {
                  cookieName: 'x-access-token',
                  cookieValue: '',
                  maxAge: this.config.ACCESS_TOKEN_AGE * 1000,
                },
                {
                  cookieName: 'x-refresh-token',
                  cookieValue: '',
                  maxAge: this.config.REFRESH_TOKEN_AGE * 1000,
                },
              ],
            });

            await this.sessionManager?.deleteSession(refreshToken);

            res.status(200).json({
              message: 'Logged out successfully!!',
              code: LogoutResponseCodes.LOGOUT_SUCCESS,
            });
          } catch (error) {
            console.error(error);
            res.status(500).json({
              message: 'Internal server error',
              code: LogoutResponseCodes.INTERNAL_SERVER_ERROR,
            });
          }
        }
      );
    };

  validateAccessToken = (req: Request, res: Response, next: NextFunction) => {
    try {
      const cookies = req.cookies;
      if (!cookies) {
        res.status(400).json({
          message: 'Cookies are not sent from the client',
          code: ValidateTokenResponseCodes.MISSING_TOKEN,
        });
        return;
      }
      const token = cookies['x-access-token'];
      if (!token) {
        res.status(400).json({
          message: 'Access token not found in the cookie',
          code: ValidateTokenResponseCodes.MISSING_TOKEN,
        });
        return;
      }

      // check if token is valid or not
      const validatedToken = verifyToken({
        token,
        tokenSecret: this.config?.TOKEN_SECRET ?? '',
      });
      if (validatedToken.code === 'EXPIRED') {
        res.status(400).json({
          message: 'Access Token is expired',
          code: ValidateTokenResponseCodes.EXPIRED_TOKEN,
        });
        return;
      }

      if (validatedToken.code === 'INVALID') {
        res.status(400).json({
          message: 'Access Token is invalid',
          code: ValidateTokenResponseCodes.INVALID_TOKEN,
        });
        return;
      }

      if (validatedToken.code === 'UNKNOWN') {
        res.status(400).json({
          message: 'Access Token is invalid',
          code: ValidateTokenResponseCodes.INVALID_TOKEN,
        });
        return;
      }

      // token is valid, call the next middleware
      // @ts-expect-error adding the token to the request
      req['accessToken'] = token;

      // @ts-expect-error adding the token payload to the request
      req['decodedAccessToken'] =
        validatedToken.code === 'VALID' ? validatedToken.data : null;
      next();
    } catch (error) {
      console.error(error);
      res.status(500).json({
        message: 'Internal server error',
        code: ValidateTokenResponseCodes.INTERNAL_SERVER_ERROR,
      });
      return;
    }
  };

  validateRefreshToken = (req: Request, res: Response, next: NextFunction) => {
    try {
      const cookies = req.cookies;
      if (!cookies) {
        res.status(400).json({
          message: 'Cookies are not sent from the client',
          code: ValidateTokenResponseCodes.MISSING_TOKEN,
        });
        return;
      }
      const token = cookies['x-refresh-token'];
      if (!token) {
        res.status(400).json({
          message: 'Refresh Token not found in the cookie',
          code: ValidateTokenResponseCodes.MISSING_TOKEN,
        });
        return;
      }

      // check if token is valid or not
      const validatedToken = verifyToken({
        token,
        tokenSecret: this.config.TOKEN_SECRET,
      });
      if (validatedToken.code === 'EXPIRED') {
        res.status(400).json({
          message: 'Token is expired',
          code: ValidateTokenResponseCodes.INVALID_TOKEN,
        });
        return;
      }

      if (validatedToken.code === 'INVALID') {
        res.status(400).json({
          message: 'Token is invalid',
          code: ValidateTokenResponseCodes.INVALID_TOKEN,
        });
        return;
      }

      if (validatedToken.code === 'UNKNOWN') {
        res.status(400).json({
          message: 'Token is invalid',
          code: ValidateTokenResponseCodes.INVALID_TOKEN,
        });
        return;
      }

      // token is valid, call the next middleware
      // @ts-expect-error adding the token to the request
      req['refreshToken'] = token;
      // @ts-expect-error adding the token payload on the request
      req['decodedRefreshToken'] =
        validatedToken.code === 'VALID' ? validatedToken.data : null;
      next();
    } catch (error) {
      console.error(error);
      res.status(500).json({
        message: 'Internal server error',
        code: ValidateTokenResponseCodes.INTERNAL_SERVER_ERROR,
      });
      return;
    }
  };

  validateSessionDeviceInfo = async (
    req: Request,
    res: Response,
    next: NextFunction
  ) => {
    const refreshToken = req.cookies['x-refresh-token'];
    const deviceInfo = extractDeviceIdentifier(req);

    if (!refreshToken) {
      return res.status(401).json({
        message: 'Unauthorized: Missing refresh token.',
        code: DeviceValidationResponseCodes.MISSING_DEVICE_TOKEN,
      });
    }

    if (!deviceInfo) {
      return res.status(401).json({
        message: 'Unauthorized: Missing device info',
        code: DeviceValidationResponseCodes.MISSING_DEVICE_INFO,
      });
    }

    try {
      if (this.sessionManager) {
        const session = await this.sessionManager.getSession(refreshToken);

        if (!session) {
          return res.status(401).json({
            message: 'Unauthorized: Session not found',
            code: DeviceValidationResponseCodes.SESSION_NOT_FOUND,
          });
        }

        const isValidDevice = await this.sessionManager.verifyDevice(
          refreshToken,
          deviceInfo
        );

        if (!isValidDevice) {
          const userEmail = await this.sessionManager.getEmailFromSession(
            refreshToken
          );
          if (userEmail) {
            this.notifyService.sendTokenStolen(userEmail);
          }
          await this.sessionManager.deleteSession(refreshToken);
          return res.status(401).json({
            message: 'Unauthorized device.',
            code: DeviceValidationResponseCodes.UNAUTHORIZED_DEVICE,
          });
        }
      }

      next();
      return;
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        message: 'Internal server error',
        code: DeviceValidationResponseCodes.INTERNAL_SERVER_ERROR,
      });
    }
  };

  createRefreshRoute: (refreshHandler: IRefreshHandler) => ExpressApplication =
    (refreshHandler) => {
      return this.app.post(
        `${this.config.BASE_PATH}/refresh`,
        this.validateRefreshToken,
        this.validateSessionDeviceInfo,
        async (req, res) => {
          try {
            // @ts-expect-error have been attached on the request
            const refreshToken = req['refreshToken'] as string;

            // @ts-expect-error have been attached on the request
            const email = req['decodedRefreshToken']?.email as string;

            if (!email) {
              res.status(400).json({
                message: 'Invalid email on the refresh token',
                code: RefreshResponseCodes.INVALID_PAYLOAD,
              });
              return;
            }

            const payload = await refreshHandler.getTokenPayload(email);

            if (typeof payload !== 'object' || 'email' in payload === false) {
              res.status(400).json({
                message: 'Invalid payload',
                code: RefreshResponseCodes.INVALID_PAYLOAD,
              });
              return;
            }

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
                  maxAge: this.config.ACCESS_TOKEN_AGE * 1000,
                },
                {
                  cookieName: 'x-refresh-token',
                  cookieValue: tokens.refreshToken,
                  maxAge: this.config.REFRESH_TOKEN_AGE * 1000,
                },
              ],
            });

            if (this.sessionManager) {
              const deviceInfo = extractDeviceIdentifier(req);
              /**
               * Delete the key from the storage
               */
              await this.sessionManager?.deleteSession(refreshToken);

              /**
               * Create a new session in the storage
               */
              this.sessionManager.storeSession(
                tokens.refreshToken,
                req.body.email,
                deviceInfo,
                this.config.REFRESH_TOKEN_AGE * 1000
              );
            }

            res.status(200).json({
              message: 'Refreshed token successfully!!',
              code: RefreshResponseCodes.REFRESH_SUCCESS,
            });
          } catch (error) {
            console.error(error);
            res.status(500).json({
              message: 'Internal server error',
              code: RefreshResponseCodes.INTERNAL_SERVER_ERROR,
            });
          }
        }
      );
    };

  createResetPasswordRoute: (
    resetPasswordHandler: IResetPasswordHandler
  ) => ExpressApplication = (resetPasswordHandler) => {
    return this.app.post(
      `${this.config.BASE_PATH}/reset`,
      this.validateAccessToken,
      async (req, res) => {
        try {
          const oldPassword = req.body.oldPassword;
          const newPassword = req.body.newPassword;

          // @ts-expect-error have been attached on the request
          const decodedToken = req['decodedAccessToken'];

          /**
           * Generate new access token and refresh token and set on the cookie
           */
          if (!(typeof decodedToken === 'object' && 'email' in decodedToken)) {
            res.status(400).json({
              message: 'Decoded token is not an object with email property',
              code: ResetPasswordResponseCodes.INVALID_PAYLOAD,
            });
            return;
          }

          const email = decodedToken['email'] as string;

          const oldPasswordHash = await resetPasswordHandler.getOldPasswordHash(
            email
          );

          const [, isOldPasswordValid] = await comparePassword({
            password: oldPassword,
            hashedPassword: oldPasswordHash,
          });
          if (!isOldPasswordValid) {
            res.status(403).json({
              message: 'Old password or username is not valid',
              code: ResetPasswordResponseCodes.INVALID_OLD_PASSWORD_USERNAME,
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
              message: 'Password could not be hashed',
              code: ResetPasswordResponseCodes.PASSWORD_HASH_ERROR,
            });
            return;
          }

          await resetPasswordHandler.saveHashedPassword(email, hashedPassword);

          /**
           * logout
           */
          setCookies({
            res,
            cookieData: [
              {
                cookieName: 'x-access-token',
                cookieValue: '',
                maxAge: 0,
              },
              {
                cookieName: 'x-refresh-token',
                cookieValue: '',
                maxAge: 0,
              },
            ],
          });

          res.status(200).json({
            message: 'Password has been reset sucessfully! Please login again',
            code: ResetPasswordResponseCodes.RESET_PASSWORD_SUCCESS,
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({
            message: 'Internal server error',
            code: ResetPasswordResponseCodes.INTERNAL_SERVER_ERROR,
          });
        }
      }
    );
  };

  createMeRoute: (meRouteHandler: IMeRouteHandler) => ExpressApplication = (
    meRouteHandler
  ) => {
    return this.app.get(
      `${this.config.BASE_PATH}/me`,
      this.validateAccessToken,
      async (req, res) => {
        try {
          // @ts-expect-error have been attached on the request
          const accessToken = req['accessToken'];

          // @ts-expect-error have been attached on the request
          const decodedToken = req['decodedAccessToken'];

          if (!(typeof decodedToken === 'object' && 'email' in decodedToken)) {
            res.status(400).json({
              message: 'Decoded token is not an object with email property',
              code: MeResponseCodes.INVALID_PAYLOAD,
            });
            return;
          }

          const email = decodedToken['email'];

          const meData = await meRouteHandler.getMeByEmail(email);

          res.status(200).json({
            data: {
              token: decodedToken,
              me: meData,
            },
            accessToken: accessToken,
            code: MeResponseCodes.ME_SUCCESS,
            message: 'Success',
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({
            message: 'Internal server error',
            code: MeResponseCodes.INTERNAL_SERVER_ERROR,
          });
        }
      }
    );
  };

  createVerifyEmailRoute: (
    verifyEmailHandler: IVerifyEmailHandler
  ) => ExpressApplication = (verifyEmailHandler) => {
    return this.app.post(
      `${this.config.BASE_PATH}/verify-email`,
      async (req, res, next) => {
        try {
          const email = req.body.email;
          const otp = req.body.otp;

          if (typeof email !== 'string') {
            res.status(400).json({
              message: 'Email invalid or not sent from the client',
              code: VerifyEmailResponseCodes.VALIDATION_FAILED,
            });
            return;
          }

          if (typeof otp !== 'string') {
            res.status(400).json({
              message: 'OTP invalid or not sent from the client',
              code: VerifyEmailResponseCodes.VALIDATION_FAILED,
            });
            return;
          }

          const isEmailAlreadyVerified =
            await verifyEmailHandler.isEmailAlreadyVerified(email);

          if (!isEmailAlreadyVerified) {
            res.status(400).json({
              message: 'Email is already verified',
              code: VerifyEmailResponseCodes.EMAIL_ALREADY_VERIFIED,
            });
            return;
          }

          const isOtpValid = this.otpService.verifyOtp(
            otp,
            this.config.OTP_SECRET
          );

          if (!isOtpValid) {
            res.status(400).json({
              message: 'OTP is invalid',
              code: VerifyEmailResponseCodes.INVALID_OTP,
            });
            return;
          }

          await verifyEmailHandler.updateIsEmailVerifiedField(email);

          this.notifyService.notifyEmailVerified(email);

          res.status(200).json({
            message: 'Email verified successfully',
            code: VerifyEmailResponseCodes.VERIFY_EMAIL_SUCCESS,
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({
            message: 'Internal server error',
            code: VerifyEmailResponseCodes.INTERNAL_SERVER_ERROR,
          });
        }
      }
    );
  };

  createSendOtpRoute: (sendOtpHandler: ISendOtpHandler) => ExpressApplication =
    (sendOtpHandler) => {
      return this.app.post(
        `${this.config.BASE_PATH}/send-otp`,
        async (req, res, next) => {
          try {
            const email = req.body.email;

            if (typeof email !== 'string') {
              res.status(400).json({
                message: 'Email is required',
                code: SendOtpResponseCodes.VALIDATION_FAILED,
              });
              return;
            }

            // validate if email is eligible for verification
            const doesUserExists = await sendOtpHandler.doesUserExists(email);

            if (!doesUserExists) {
              res.status(400).json({
                message:
                  "User with that email doesn't exist. Please create an account",
                code: SendOtpResponseCodes.USER_NOT_FOUND,
              });
              return;
            }

            const otp = this.otpService.generateOtp(this.config.OTP_SECRET);

            this.notifyService.sendOtp(email, {
              code: otp,
            });

            res.status(200).json({
              message: 'OTP sent successfully',
              code: SendOtpResponseCodes.SEND_OTP_SUCCESS,
            });
          } catch (error) {
            console.error(error);
            res.status(500).json({
              message: 'Internal server error',
              code: SendOtpResponseCodes.INTERNAL_SERVER_ERROR,
            });
          }
        }
      );
    };

  createForgotPasswordRoute: (
    forgotPasswordHandler: IForgotPasswordHandler
  ) => ExpressApplication = (forgotPasswordHandler) => {
    return this.app.post(
      `${this.config.BASE_PATH}/forgot-password`,
      async (req, res, next) => {
        try {
          const email = req.body.email;
          const otp = req.body.otp;
          const newPassword = req.body.newPassword;

          if (typeof email !== 'string') {
            res.status(400).json({
              message: 'Email is required',
              code: ForgotPasswordResponseCodes.VALIDATION_FAILED,
            });
            return;
          }

          if (typeof otp !== 'string') {
            res.status(400).json({
              message: 'OTP is required',
              code: ForgotPasswordResponseCodes.VALIDATION_FAILED,
            });
            return;
          }

          if (typeof newPassword !== 'string') {
            res.status(400).json({
              message: 'New password is required',
              code: ForgotPasswordResponseCodes.VALIDATION_FAILED,
            });
            return;
          }

          const isOtpValid = await this.otpService.verifyOtp(
            otp,
            this.config.OTP_SECRET
          );

          if (!isOtpValid) {
            res.status(400).json({
              message: 'Invalid OTP',
              code: ForgotPasswordResponseCodes.INVALID_OTP,
            });
            return;
          }

          const [, hashedPassword] = await hashPassword(
            newPassword,
            this.config.SALT_ROUNDS
          );

          if (!hashedPassword) {
            res.status(500).json({
              message: 'Password could not be hashed',
              code: ForgotPasswordResponseCodes.PASSWORD_HASH_ERROR,
            });
            return;
          }

          await forgotPasswordHandler.saveNewPassword(email, hashedPassword);

          res.status(200).json({
            message: 'Password changed successfully',
            code: ForgotPasswordResponseCodes.FORGOT_PASSWORD_SUCCESS,
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({
            message: 'Internal server error',
            code: ForgotPasswordResponseCodes.INTERNAL_SERVER_ERROR,
          });
        }
      }
    );
  };
}

export const validateAccessToken = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const cookies = req.cookies;
    if (!cookies) {
      res.status(400).json({
        message: 'Cookies are not sent from the client',
        code: ValidateTokenResponseCodes.MISSING_TOKEN,
      });
      return;
    }
    const token = cookies['x-access-token'];
    if (!token) {
      res.status(400).json({
        message: 'Access token not found in the cookie',
        code: ValidateTokenResponseCodes.MISSING_TOKEN,
      });
      return;
    }

    const secret = process.env['TOKEN_SECRET'];
    if (!secret) {
      res.status(500).json({
        message: 'Please set `TOKEN_SECRET` in the env variable',
        code: ValidateTokenResponseCodes.INTERNAL_SERVER_ERROR,
      });
      return;
    }

    // check if token is valid or not
    const validatedToken = verifyToken({
      token,
      tokenSecret: secret,
    });
    if (validatedToken.code === 'EXPIRED') {
      res.status(400).json({
        message: 'Access Token is expired',
        code: ValidateTokenResponseCodes.EXPIRED_TOKEN,
      });
      return;
    }

    if (validatedToken.code === 'INVALID') {
      res.status(400).json({
        message: 'Access Token is invalid',
        code: ValidateTokenResponseCodes.INVALID_TOKEN,
      });
      return;
    }

    if (validatedToken.code === 'UNKNOWN') {
      res.status(400).json({
        message: 'Access Token is invalid',
        code: ValidateTokenResponseCodes.INVALID_TOKEN,
      });
      return;
    }

    // token is valid, call the next middleware
    // @ts-expect-error adding the token to the request
    req['accessToken'] = token;

    // @ts-expect-error adding the token payload to the request
    req['decodedAccessToken'] =
      validatedToken.code === 'VALID' ? validatedToken.data : null;
    next();
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: 'Internal server error',
      code: ValidateTokenResponseCodes.INTERNAL_SERVER_ERROR,
    });
    return;
  }
};
