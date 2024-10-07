export { RouteGenerator } from './lib/auth';
export {
  ISignUpPersistor,
  ILoginPersistor,
  ILogoutPersistor,
  IRefreshPersistor,
  IResetPasswordPersistor,
  IMeRoutePersistor,
  IVerifyEmailPersistor,
  IForgotPasswordPersistor,
  IVerifyOtpPersistor,
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
