import {
  ISignUpHandler,
  ILoginHandler,
  ILogoutHandler,
  IRefreshHandler,
  IResetPasswordHandler,
  IMeRouteHandler,
  IVerifyEmailHandler,
  IForgotPasswordHandler,
  ISendOtpHandler,
} from '../auth-interfaces';

export type TUser = {
  name: string;
  email: string;
  password: string;
  is_email_verified: boolean;
  otps: {
    code: string;
    generatedAt: number;
  }[];
};

let users: TUser[] = [];

type TEmailObj = {
  email: string;
};

interface TSignUpBodyInput extends TEmailObj {
  name: string;
  password: string;
}

export class SignUpHandler implements ISignUpHandler {
  constructor() {
    console.log('signup persistor init...');
  }

  errors: { USER_ALREADY_EXISTS_MESSAGE?: string } = {};

  doesUserExists: (body: TSignUpBodyInput) => Promise<boolean> = async (
    body
  ) => {
    const user = users.find((user) => user.email === body.email);
    return !!user;
  };

  saveUser: (body: TSignUpBodyInput, hashedPassword: string) => Promise<void> =
    async (body, hashedPassword) => {
      users.push({
        name: body.name,
        email: body.email,
        password: hashedPassword,
        /**
         * !!for testing...
         */
        is_email_verified: true,
        otps: [],
      });
    };
}

export class LoginHandler implements ILoginHandler {
  getUserByEmail: (email: string) => Promise<TUser | null> = async (email) => {
    const user = await users.find((user) => user.email === email);

    if (!user) {
      return null;
    }

    return user;
  };
  errors: { PASSWORD_OR_EMAIL_INCORRECT?: string } = {
    PASSWORD_OR_EMAIL_INCORRECT: 'Password or email incorrect',
  };

  getTokenPayload: (email: string) => Promise<{
    name: string;
    email: string;
  } | null> = async (email) => {
    const user = users.find((user) => user.email === email);

    if (!user) {
      return null;
    }

    return {
      email: user?.email,
      name: user?.name,
    };
  };
}

export class LogoutHandler implements ILogoutHandler {
  shouldLogout: () => Promise<boolean> = async () => {
    return true;
  };
}

export class RefreshHandler implements IRefreshHandler {
  errors: { INVALID_REFRESH_TOKEN?: string } = {};

  refresh: (token: string) => Promise<void> = async () => {
    console.log('refreshing token...');
  };

  getTokenPayload: (email: string) => Promise<{
    name: string;
    email: string;
  } | null> = async (email) => {
    const user = users.find((user) => user.email === email);

    if (!user) {
      return null;
    }

    return {
      email: user?.email,
      name: user?.name,
    };
  };
}

export class ResetPasswordHandler implements IResetPasswordHandler {
  saveHashedPassword: (email: string, hashedPassword: string) => Promise<void> =
    async (email, hashedPassword) => {
      const userIdx = users.findIndex((user) => user.email === email);
      if (userIdx < 0) {
        throw new Error(`User not found`);
      }

      users[userIdx].password = hashedPassword;
    };
  getOldPasswordHash: (email: string) => Promise<string> = async (email) => {
    const user = users.find((user) => user.email === email);
    if (!user) {
      return '';
    }
    return user.password;
  };
}

export class MeRouteHandler implements IMeRouteHandler {
  getMeByEmail: (
    email: string
  ) => Promise<{ email: string; name: string } | null> = async (email) => {
    const user = users.find((user) => user.email === email);

    if (!user) {
      return null;
    }

    return {
      name: user?.name,
      email: user?.email,
    };
  };
}

export class VerifyEmailHandler implements IVerifyEmailHandler {
  updateEmailVerificationStatusAndValidateOtp: (
    email: string,
    otp: string
  ) => Promise<boolean> = async (email, otp) => {
    const user = users.find((user) => user.email === email);
    if (!user) {
      return false;
    }
    const lastOtp = user.otps[user.otps.length - 1];

    const isOtpMatched = lastOtp?.code === otp;

    const isExpired = lastOtp?.generatedAt < Date.now() / 1000 - 60 * 5; // 5 minutes

    /**
     * update the `is_email_verified` field
     */
    users = users.map((u) => {
      if (u.email === email) {
        return {
          ...u,
          is_email_verified: true,
        };
      }
      return u;
    });

    return isOtpMatched && !isExpired;
  };

  isEmailAlreadyVerified: (email: string) => Promise<boolean> = async (
    email
  ) => {
    const user = users.find((user) => user.email === email);

    return !user?.is_email_verified;
  };

  updateIsEmailVerifiedField: (email: string) => Promise<void> = async (
    email
  ) => {
    users = users.map((u) => {
      if (u.email === email) {
        return {
          ...u,
          is_email_verified: true,
        };
      }
      return u;
    });
  };
}

export class SendOtpHandler implements ISendOtpHandler {
  doesUserExists: (email: string) => Promise<boolean> = async (email) => {
    const user = users.find((user) => user.email === email);
    return !!user;
  };

  saveOtp: (
    email: string,
    otp: { code: string; generatedAt: number }
  ) => Promise<void> = async (email, otp) => {
    const userIdx = users.findIndex((user) => user.email === email);
    if (userIdx < 0) {
      throw new Error(`User not found`);
    }
    users[userIdx].otps.push(otp);
  };
}

export class ForgotPasswordHandler implements IForgotPasswordHandler {
  isOtpValid: (email: string, otp: string) => Promise<boolean> = async (
    email,
    otp
  ) => {
    const user = users.find((user) => user.email === email);
    if (!user) {
      return false;
    }
    const lastOtp = user.otps[user.otps.length - 1];

    const isOtpMatched = lastOtp?.code === otp;

    const isExpired = lastOtp?.generatedAt < Date.now() / 1000 - 60 * 5; // 5 minutes

    return isOtpMatched && !isExpired;
  };

  saveNewPassword: (email: string, password: string) => Promise<void> = async (
    email,
    password
  ) => {
    const userIdx = users.findIndex((user) => user.email === email);
    if (userIdx < 0) {
      throw new Error(`User not found`);
    }
    users[userIdx].password = password;
  };
}
