import {
  ILoginPersistor,
  ILogoutPersistor,
  IRefreshPersistor,
  IResetPasswordPersistor,
  ISignUpPersistor,
  IMeRoutePersistor,
  IVerifyEmailPersistor,
} from '../../index';

import { prisma } from './prisma-client';

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
    const user = await prisma.user.findUnique({
      where: {
        email: body.email,
      },
    });
    return !!user;
  };

  saveUser: (body: TSignUpBodyInput, hashedPassword: string) => Promise<void> =
    async (body, hashedPassword) => {
      await prisma.user.create({
        data: {
          name: body.name,
          email: body.email,
          password: hashedPassword,
        },
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
    const user = await prisma.user.findUnique({
      where: {
        email,
      },
    });
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
    const user = await prisma.user.findUnique({ where: { email } });

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
  revokeTokens: (token: {
    refreshToken: string;
    accessToken: string;
  }) => Promise<boolean> = async (token) => {
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
    console.log('getTokenPayload', email);
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
      throw new Error('User not found');
    }

    return {
      email: user?.email,
      name: user?.name,
    };
  };

  // !FIXME: token revocation feature
  isTokenEligibleForRefresh: (token: string) => Promise<boolean> = async () => {
    return true;
  };
}

export class ResetPasswordPersistor implements IResetPasswordPersistor {
  saveHashedPassword: (email: string, hashedPassword: string) => Promise<void> =
    async (email, hashedPassword) => {
      await prisma.user.update({
        where: {
          email,
        },
        data: {
          password: hashedPassword,
        },
      });
    };
  getOldPasswordHash: (email: string) => Promise<string> = async (email) => {
    const user = await prisma.user.findFirst({
      where: {
        email,
      },
    });
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
  getMeByEmail: () => Promise<any> = async () => {
    console.log('getting logged in user...');
  };
}

export class VerifyEmailPersistor implements IVerifyEmailPersistor {
  errors: { EMAIL_NOT_ELIGIBLE_FOR_VERIFICATION?: string } = {
    EMAIL_NOT_ELIGIBLE_FOR_VERIFICATION: '',
  };

  isEmailEligibleForVerification: (email: string) => Promise<boolean> = async (
    email
  ) => {
    const user = await prisma.user.findFirst({
      where: {
        email,
      },
    });
    console.log('user', user);

    return !user?.is_email_verified;
  };

  sendVerificationEmail: (input: {
    email: string;
    verificationPath: string;
  }) => Promise<void> = async (input) => {
    console.log('sendVerificationEmail Input', input);
  };
}
