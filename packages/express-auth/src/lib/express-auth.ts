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
  IForgotPasswordPersistor,
  ILoginPersistor,
  ILogoutPersistor,
  IMeRoutePersistor,
  IRefreshPersistor,
  IResetPasswordPersistor,
  IRouteGenerator,
  IRouteMiddlewares,
  ISignUpPersistor,
  IVerifyEmailPersistor,
  IVerifyOtpPersistor,
  TConfig,
} from './auth-interfaces';
import { INotifyService, SessionManager } from './session-interfaces';
import { MemoryStorage } from './session-storage';

export class RouteGenerator<P, Q, R, S>
  implements IRouteGenerator<P, Q, R, S>, IRouteMiddlewares
{
  constructor(
    private app: ExpressApplication,
    private notifyService: INotifyService,
    private config: TConfig,
    private sessionManager?: SessionManager
  ) {
    if (!this.sessionManager) {
      /**
       * Use the memory storage by default
       */
      this.sessionManager = new SessionManager(new MemoryStorage());
    }
  }

  createSignUpRoute(signUpPersistor: ISignUpPersistor<P>) {
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
            });
            return;
          }

          if (!req.body.password) {
            res.status(400).json({
              message: 'Password is required',
            });
            return;
          }

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
        } catch (error) {
          console.error(error);
          res.status(500).json({
            message: 'Internal server error',
          });
        }
      }
    );
  }

  createLoginRoute(logingPersistor: ILoginPersistor<Q>) {
    return this.app.post(`${this.config.BASE_PATH}/login`, async (req, res) => {
      try {
        if (!req.body.email) {
          res.status(400).json({
            message: 'Email is required',
          });
          return;
        }

        if (!req.body.password) {
          res.status(400).json({
            message: 'Password is required',
          });
          return;
        }

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
          tokenSecret: this.config.TOKEN_SECRET,
          ACCESS_TOKEN_AGE: this.config.ACCESS_TOKEN_AGE,
          REFRESH_TOKEN_AGE: this.config.REFRESH_TOKEN_AGE,
        });

        const deviceInfo = extractDeviceIdentifier(req);

        if (this.sessionManager) {
          this.sessionManager.storeSession(
            tokens.refreshToken,
            req.body.email,
            deviceInfo
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
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({
          message: 'Internal server error',
        });
      }
    });
  }

  createLogoutRoute(logoutPersistor: ILogoutPersistor) {
    return this.app.post(
      `${this.config.BASE_PATH}/logout`,
      this.validateAccessToken.bind(this),
      this.validateRefreshToken.bind(this),
      this.validateSessionDeviceInfo.bind(this),

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
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({
            message: 'Internal server error',
          });
        }
      }
    );
  }

  validateAccessToken(req: Request, res: Response, next: NextFunction) {
    try {
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
        tokenSecret: this.config.TOKEN_SECRET,
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
    } catch (error) {
      console.error(error);
      res.status(500).json({
        message: 'Internal server error',
      });
      return;
    }
  }

  validateRefreshToken(req: Request, res: Response, next: NextFunction) {
    try {
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
    } catch (error) {
      console.error(error);
      res.status(500).json({
        message: 'Internal server error',
      });
      return;
    }
  }

  async validateSessionDeviceInfo(
    req: Request,
    res: Response,
    next: NextFunction
  ) {
    const refreshToken = req.cookies['x-refresh-token'];
    const deviceInfo = extractDeviceIdentifier(req);

    if (!refreshToken) {
      return res.status(401).send('Unauthorized: Missing refresh token.');
    }

    if (!deviceInfo) {
      return res.status(401).send('Unauthorized: Missing device info');
    }

    try {
      if (this.sessionManager) {
        const session = await this.sessionManager.getSession(refreshToken);

        if (!session) {
          return res.status(401).send('Unauthorized: Session not found');
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
            this.notifyService.notify('TOKEN_STOLEN', userEmail);
          }
          await this.sessionManager.deleteSession(refreshToken);
          return res.status(401).send('Unauthorized device.');
        }
      }

      next();
      return;
    } catch (error) {
      console.error(error);
      return res
        .status(500)
        .send('Internal server error during authentication');
    }
  }

  createRefreshRoute(refreshPersistor: IRefreshPersistor<R>) {
    return this.app.post(
      `${this.config.BASE_PATH}/refresh`,
      this.validateRefreshToken,
      this.validateSessionDeviceInfo.bind(this),
      async (req, res) => {
        try {
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-expect-error
          const refreshToken = req['refreshToken'] as string;

          // validate the refreshToken
          const decodedToken = await verifyToken({
            token: refreshToken,
            tokenSecret: this.config.TOKEN_SECRET,
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

          res.status(200).json({
            message: 'Refreshed token successfully!!',
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({
            message: 'Internal server error',
          });
        }
      }
    );
  }

  createResetPasswordRoute(resetPasswordPersistor: IResetPasswordPersistor) {
    return this.app.post(
      `${this.config.BASE_PATH}/reset`,
      this.validateAccessToken.bind(this),
      this.validateSessionDeviceInfo.bind(this),
      async (req, res) => {
        try {
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
            tokenSecret: this.config.TOKEN_SECRET,
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

          const oldPasswordHash =
            await resetPasswordPersistor.getOldPasswordHash(email);

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
            this.config.SALT_ROUNDS
          );

          if (!hashedPassword) {
            res.status(500).json({
              message: 'Password could not be hashed',
            });
            return;
          }

          await resetPasswordPersistor.saveHashedPassword(
            email,
            hashedPassword
          );

          /**
           * logout
           */
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

          res.status(200).json({
            message: 'Password has been reset sucessfully! Please login again',
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({
            message: 'Internal server error',
          });
        }
      }
    );
  }

  createMeRoute(meRoutePersistor: IMeRoutePersistor<S>) {
    return this.app.get(
      `${this.config.BASE_PATH}/me`,
      this.validateAccessToken.bind(this),
      this.validateSessionDeviceInfo.bind(this),
      async (req, res) => {
        try {
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-expect-error
          const accessToken = req.accessToken;

          const decodedToken = verifyToken({
            token: accessToken,
            tokenSecret: this.config.TOKEN_SECRET,
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
        } catch (error) {
          console.error(error);
          res.status(500).json({
            message: 'Internal server error',
          });
        }
      }
    );
  }

  createVerifyEmailRoute: (
    verifyEmailPersistor: IVerifyEmailPersistor
  ) => ExpressApplication = (verifyEmailPersistor) => {
    return this.app.post(
      `${this.config.BASE_PATH}/verify-email`,
      async (req, res, next) => {
        try {
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
                verifyEmailPersistor.errors
                  .EMAIL_NOT_ELIGIBLE_FOR_VERIFICATION ||
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
        } catch (error) {
          console.error(error);
          res.status(500).json({
            message: 'Internal server error',
          });
        }
      }
    );
  };

  createForgotPasswordRoute: (
    forgotPasswordPersistor: IForgotPasswordPersistor
  ) => ExpressApplication = (forgotPasswordPersistor) => {
    return this.app.post(
      `${this.config.BASE_PATH}/forgot-password`,
      async (req, res, next) => {
        try {
          const email = req.body.email;

          if (typeof email !== 'string') {
            res.status(400).json({
              message: 'Email invalid or not sent from the client',
            });
            return;
          }

          // validate if email is eligible for verification
          const doesUserExists = await forgotPasswordPersistor.doesUserExists(
            email
          );

          if (!doesUserExists) {
            res.status(400).json({
              message:
                "User with that email doesn't exist. Please create an account",
            });
            return;
          }

          const otp = this.generateOTP();

          await forgotPasswordPersistor.saveOtp(email, otp);

          forgotPasswordPersistor.sendOtp(email, {
            code: otp.code,
            generatedAt: otp.generatedAt,
          });

          res.status(200).json({
            message: 'OTP sent successfully',
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({
            message: 'Internal server error',
          });
        }
      }
    );
  };

  createVerifyOtpRoute: (
    verifyOtpPersistor: IVerifyOtpPersistor
  ) => ExpressApplication = (verifyOtpPersistor) => {
    return this.app.post(
      `${this.config.BASE_PATH}/verify-otp`,
      async (req, res, next) => {
        try {
          const email = req.body.email;
          const otp = req.body.otp;
          const newPassword = req.body.newPassword;

          if (typeof email !== 'string') {
            res.status(400).json({
              message: 'Email invalid or not sent from the client',
            });
            return;
          }

          if (typeof otp !== 'string') {
            res.status(400).json({
              message: 'OTP invalid or not sent from the client',
            });
            return;
          }

          if (typeof newPassword !== 'string') {
            res.status(400).json({
              message: 'New password invalid or not sent from the client',
            });
            return;
          }

          const isOtpValid = await verifyOtpPersistor.isOtpValid(email, otp);

          if (!isOtpValid) {
            res.status(400).json({
              message: 'Invalid OTP',
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
            });
            return;
          }

          await verifyOtpPersistor.saveNewPassword(email, hashedPassword);

          res.status(200).json({
            message: 'OTP verified successfully',
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({
            message: 'Internal server error',
          });
        }
      }
    );
  };

  private generateEmailVerificationPath(email: string): string {
    const tokens = generateTokens(
      { email },
      {
        ACCESS_TOKEN_AGE: this.config.EMAIL_VERIFICATION_TOKEN_AGE,
        REFRESH_TOKEN_AGE: this.config.REFRESH_TOKEN_AGE,
        tokenSecret: this.config.TOKEN_SECRET,
      }
    );

    return `${this.config.BASE_PATH}/verify-email?token=${tokens.accessToken}`;
  }

  private generateOTP() {
    const code = `${Math.floor(100000 + Math.random() * 900000)}`;
    const generatedAt = Date.now() / 1000;

    return {
      code,
      generatedAt,
    };
  }
}
