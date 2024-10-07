export { RouteGenerator } from './lib/auth';
export {
  ISignUpHandler as ISignUpPersistor,
  ILoginHandler as ILoginPersistor,
  ILogoutHandler as ILogoutPersistor,
  IRefreshHandler as IRefreshPersistor,
  IResetPasswordHandler as IResetPasswordPersistor,
  IMeRouteHandler as IMeRoutePersistor,
  IVerifyEmailHandler as IVerifyEmailPersistor,
  IForgotHandler as IForgotPasswordPersistor,
  IVerifyOtpHandler as IVerifyOtpPersistor,
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
