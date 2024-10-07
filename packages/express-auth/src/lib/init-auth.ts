import {
  IForgotHandler,
  ILoginHandler,
  ILogoutHandler,
  IMeRouteHandler,
  IRefreshHandler,
  IResetPasswordHandler,
  ISignUpHandler,
  IVerifyEmailHandler,
  IVerifyOtpHandler,
} from './auth-interfaces';
import { RouteGenerator } from './auth';

export function initAuth({
  routeGenerator,
  signUpPersistor,
  loginPersistor,
  logoutPersistor,
  refreshPersistor,
  resetPasswordPersistor,
  meRoutePersistor,
  verifyEmailPersistor,
  forgotPasswordPersistor,
  verifyOtpPersistor,
}: {
  routeGenerator: RouteGenerator;
  signUpPersistor: ISignUpHandler;
  loginPersistor: ILoginHandler;
  logoutPersistor: ILogoutHandler;
  refreshPersistor: IRefreshHandler;
  resetPasswordPersistor: IResetPasswordHandler;
  meRoutePersistor: IMeRouteHandler;
  verifyEmailPersistor: IVerifyEmailHandler;
  forgotPasswordPersistor: IForgotHandler;
  verifyOtpPersistor: IVerifyOtpHandler;
}) {
  // sign up route
  routeGenerator.createSignUpRoute(signUpPersistor);

  // login route
  routeGenerator.createLoginRoute(loginPersistor);

  // logout route
  routeGenerator.createLogoutRoute(logoutPersistor);

  // refresh route
  routeGenerator.createRefreshRoute(refreshPersistor);

  // reset password route
  routeGenerator.createResetPasswordRoute(resetPasswordPersistor);

  // me route
  routeGenerator.createMeRoute(meRoutePersistor);

  // verify email route
  routeGenerator.createVerifyEmailRoute(verifyEmailPersistor);

  // forgot password route
  routeGenerator.createForgotPasswordRoute(forgotPasswordPersistor);

  // verify otp route
  routeGenerator.createVerifyOtpRoute(verifyOtpPersistor);

  return routeGenerator;
}
