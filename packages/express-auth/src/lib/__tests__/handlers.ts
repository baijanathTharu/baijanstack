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
  IOAuthHandler,
  AuthProvider,
} from '../auth-interfaces';

export type TUser = {
  name: string;
  email: string;
  password: string;
  is_email_verified: boolean;
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
        is_email_verified: false,
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
}

export class ForgotPasswordHandler implements IForgotPasswordHandler {
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

export class OAuthHandler implements IOAuthHandler {
  createOrUpdateUser: (payload: {
    email: string;
    providerId: string;
    provider: AuthProvider;
    displayName?: string;
  }) => Promise<boolean> = async (payload) => {
    const userIdx = users.findIndex((user) => user.email === payload.email);

    if (userIdx >= 0) {
      users[userIdx] = {
        ...users[userIdx],
        name: payload.displayName || users[userIdx].name,
      };

      return true;
    } else {
      users.push({
        name: payload.displayName || '',
        email: payload.email,
        password: '', // Password is not used for OAuth users
        is_email_verified: true, // Assume email is verified for OAuth users
      });

      console.log('New user created:', users[users.length - 1]);
      return true;
    }
  };

  getTokenPayload: (email: string) => Promise<any> = async (email) => {
    const user = users.find((user) => user.email === email);

    if (!user) {
      return null;
    }

    return {
      email: user.email,
      name: user.name,
    };
  };
}
