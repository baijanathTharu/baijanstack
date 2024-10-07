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
  IVerifyOtpHandler,
  TConfig,
} from './lib/auth-interfaces';

export {
  ISessionManager,
  IStorageManager,
  INotifyService,
  SessionManager,
} from './lib/session-interfaces';

export { MemoryStorage } from './lib/session-storage';

export { initAuth } from './lib/init-auth';
