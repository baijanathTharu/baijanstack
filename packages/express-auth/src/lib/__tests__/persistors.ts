import {
  ISignUpPersistor,
  ILoginPersistor,
  ILogoutPersistor,
  IRefreshPersistor,
  IResetPasswordPersistor,
  IMeRoutePersistor,
  IVerifyEmailPersistor,
} from '../auth-interfaces';
import { INotifyService } from '../session-interfaces';

export type TUser = {
  name: string;
  email: string;
  password: string;
  is_email_verified: boolean;
};

const users: TUser[] = [];

type TEmailObj = {
  email: string;
};

interface TSignUpBodyInput extends TEmailObj {
  name: string;
  password: string;
}

export class SignUpPersistor implements ISignUpPersistor<TSignUpBodyInput> {
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
      });
    };
}

type TLoginOutput = {
  name: string;
  email: string;
  password: string;
};

export class LoginPersistor implements ILoginPersistor<TLoginOutput> {
  getUserByEmail: (email: string) => Promise<any> = async (email) => {
    const user = await users.find((user) => user.email === email);

    if (!user) {
      throw new Error('User not found');
    }

    return user;
  };
  errors: { PASSWORD_OR_EMAIL_INCORRECT?: string } = {
    PASSWORD_OR_EMAIL_INCORRECT: 'Password or email incorrect',
  };
  login: () => Promise<void> = async () => {
    console.log('logged in successfully!!');
  };

  getTokenPayload: (email: string) => Promise<{
    name: string;
    email: string;
  }> = async (email) => {
    const user = users.find((user) => user.email === email);

    if (!user) {
      throw new Error('User not found');
    }

    return {
      email: user?.email,
      name: user?.name,
    };
  };
}

export class LogoutPersistor implements ILogoutPersistor {
  shouldLogout: () => Promise<boolean> = async () => {
    return true;
  };
}

type TRefreshOutput = {
  email: string;
  name: string;
};

export class RefreshPersistor implements IRefreshPersistor<TRefreshOutput> {
  errors: { INVALID_REFRESH_TOKEN?: string } = {};

  refresh: (token: string) => Promise<void> = async () => {
    console.log('refreshing token...');
  };

  getTokenPayload: (email: string) => Promise<any> = async (email) => {
    const user = users.find((user) => user.email === email);

    if (!user) {
      throw new Error('User not found');
    }

    return {
      email: user?.email,
      name: user?.name,
    };
  };
}

export class ResetPasswordPersistor implements IResetPasswordPersistor {
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
      throw new Error(`User not found`);
    }
    return user.password;
  };
}

type TMeOutput = {
  name: string;
  email: string;
};

export class MeRoutePersistor implements IMeRoutePersistor<TMeOutput> {
  getMeByEmail: (email: string) => Promise<any> = async (email) => {
    const user = users.find((user) => user.email === email);

    if (!user) {
      throw new Error('User not found');
    }

    return {
      name: user?.name,
      email: user?.email,
    };
  };
}

export class VerifyEmailPersistor implements IVerifyEmailPersistor {
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

export class EmailNotificationService implements INotifyService {
  async notify(type: 'TOKEN_STOLEN', email: string): Promise<void> {
    if (type === 'TOKEN_STOLEN') {
      console.log(`Notifying | ${type} | Email: ${email}`);
    }
  }
}
