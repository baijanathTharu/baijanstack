export { RouteGenerator } from './lib/auth';
export {
  ISignUpHandler,
  ILoginHandler,
  ILogoutHandler,
  IRefreshHandler,
  IResetPasswordHandler,
  IMeRouteHandler,
  IVerifyEmailHandler,
  IForgotPasswordHandler,
  ISendOtpHandler,
  TConfig,
  IOAuthHandler,
  AuthProvider,
} from './lib/auth-interfaces';

export {
  ISessionManager,
  IStorageManager,
  INotifyService,
  SessionManager,
} from './lib/session-interfaces';

export { MemoryStorage } from './lib/session-storage';

export { initAuth } from './lib/init-auth';

export {
  SignUpResponseCodes,
  LoginResponseCodes,
  LogoutResponseCodes,
  RefreshResponseCodes,
  ResetPasswordResponseCodes,
  MeResponseCodes,
  VerifyEmailResponseCodes,
  SendOtpResponseCodes,
  ForgotPasswordResponseCodes,
  ValidateTokenResponseCodes,
} from './lib/response-codes';

export { validateAccessToken, validateAuthWithToken } from './lib/auth';

export type {
  TSignUpResponseCodes,
  TLoginResponseCodes,
  TLogoutResponseCodes,
  TRefreshResponseCodes,
  TResetPasswordResponseCodes,
  TMeResponseCodes,
  TVerifyEmailResponseCodes,
  TSendOtpResponseCodes,
  TForgotPasswordResponseCodes,
  TValidateTokenResponseCodes,
} from './lib/response-codes';

export { GoogleAuthGenerator } from './lib/oauth/google';
