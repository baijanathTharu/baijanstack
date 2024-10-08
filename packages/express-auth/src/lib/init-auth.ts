import {
  IForgotPasswordHandler,
  ILoginHandler,
  ILogoutHandler,
  IMeRouteHandler,
  IRefreshHandler,
  IResetPasswordHandler,
  ISignUpHandler,
  IVerifyEmailHandler,
  ISendOtpHandler,
} from './auth-interfaces';
import { RouteGenerator } from './auth';

export function initAuth({
  routeGenerator,
  signUpHandler,
  loginHandler,
  logoutHandler,
  refreshHandler,
  resetPasswordHandler,
  meRouteHandler,
  verifyEmailHandler,
  forgotPasswordHandler,
  sendOtpHandler,
}: {
  routeGenerator: RouteGenerator;
  signUpHandler: ISignUpHandler;
  loginHandler: ILoginHandler;
  logoutHandler: ILogoutHandler;
  refreshHandler: IRefreshHandler;
  resetPasswordHandler: IResetPasswordHandler;
  meRouteHandler: IMeRouteHandler;
  verifyEmailHandler: IVerifyEmailHandler;
  forgotPasswordHandler: IForgotPasswordHandler;
  sendOtpHandler: ISendOtpHandler;
}) {
  // sign up route
  routeGenerator.createSignUpRoute(signUpHandler);

  // login route
  routeGenerator.createLoginRoute(loginHandler);

  // logout route
  routeGenerator.createLogoutRoute(logoutHandler);

  // refresh route
  routeGenerator.createRefreshRoute(refreshHandler);

  // reset password route
  routeGenerator.createResetPasswordRoute(resetPasswordHandler);

  // me route
  routeGenerator.createMeRoute(meRouteHandler);

  // verify email route
  routeGenerator.createVerifyEmailRoute(verifyEmailHandler);

  // forgot password route
  routeGenerator.createForgotPasswordRoute(forgotPasswordHandler);

  // verify otp route
  routeGenerator.createSendOtpRoute(sendOtpHandler);

  return routeGenerator;
}
