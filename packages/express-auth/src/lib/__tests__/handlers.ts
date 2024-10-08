import {
  ISignUpHandler,
  ILoginHandler,
  ILogoutHandler,
  IRefreshHandler,
  IResetPasswordHandler,
  IMeRouteHandler,
  IVerifyEmailHandler,
  IForgotPasswordHandler,
  IForgotPasswordHandler,
} from '../auth-interfaces';
import { INotifyService } from '../session-interfaces';

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

const users: TUser[] = [];

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
        is_email_verified: false,
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
  errors: { EMAIL_NOT_ELIGIBLE_FOR_VERIFICATION?: string } = {
    EMAIL_NOT_ELIGIBLE_FOR_VERIFICATION: '',
  };

  isEmailEligibleForVerification: (email: string) => Promise<boolean> = async (
    email
  ) => {
    const user = users.find((user) => user.email === email);

    return !user?.is_email_verified;
  };

  sendVerificationEmail: (input: {
    email: string;
    verificationPath: string;
  }) => Promise<void> = async (input) => {
    console.log('sendVerificationEmail Input', input);
  };
}

export class ForgotPasswordHandler implements IForgotPasswordHandler {
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

  sendOtp: (
    email: string,
    otp: { code: string; generatedAt: number }
  ) => Promise<void> = async (email, otp) => {
    console.log('sendOtp', email, otp);
  };
}

export class VerifyOtpHandler implements IForgotPasswordHandler {
  isOtpValid: (email: string, otp: string) => Promise<boolean> = async (
    email,
    otp
  ) => {
    const user = users.find((user) => user.email === email);
    if (!user) {
      return false;
    }
    const lastOtp = user.otps[user.otps.length - 1];

    if (!lastOtp) {
      return false;
    }

    if (lastOtp.code !== otp) {
      return false;
    }

    const isExpired = lastOtp.generatedAt < Date.now() / 1000 - 60 * 5; // 5 minutes
    return !isExpired;
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

export class EmailNotificationService implements INotifyService {
  async notify(type: 'TOKEN_STOLEN', email: string): Promise<void> {
    if (type === 'TOKEN_STOLEN') {
      console.log(`Notifying | ${type} | Email: ${email}`);
    }
  }
}
