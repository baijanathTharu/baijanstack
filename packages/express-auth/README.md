# express-auth

> ! This library is under active development. Please do not use it in production.

This is an authentication library for express. It uses email-password authentication flow for authentication.

## Motivation

The motivation behind creating this library is to reduce the boilerplate code for authentication that we have to write when implementing authentication in any express application.

## Principles

We have used two principles to implement this library.

- One is to generate routes for authentication.
- The other is to provide the interface for the persistence layer.

The route generator takes care of generating the routes for authentication. The persistence layer provides the interface for the persistence layer which is implemented by the user.

## Generated Routes

The following routes are generated for authentication.

### {BASE_PATH}/signup

This route handles sign up of new user.

> Request Body must have email and password properties:

```json
{
  "email": "baijan@test.com",
  "password": "baijan",
  "name": "baijan"
}
```

When you sign up, we will hash the password and \*send the email for verification. We will store the hashed password in the storage using the implementation provided.

### /verify-email

This route is used to verify the email after signing up.

> Still in progress

### /login

This route handles login of user.

> Request Body must have email and password properties:

```json
{
  "email": "baijan@test.com",
  "password": "baijan"
}
```

### /logout

This route log outs user from the application. We will invalidate the refresh token.

### /refresh

This route refreshes the access token and refresh token if refresh token is valid.

### /me

This route returns the details of logged in user.

### /reset-password

This route resets the password of the logged in user.

### /forgot-password

This route sends the OTP to change the password.

> Request Body must have email property:

```json
{
  "email": "baijan@test.com"
}
```

### /verify-otp

This route is used to update the password. User must send the new password and OTP obtained in the email.

> Request Body must have email and otp properties:

```json
{
  "email": "baijan@test.com",
  "otp": "123456"
}
```

## Usage

- Install the dependency.

```bash
npm install @baijanstack/express-auth
```

- Create the auth configuration

```ts
import { TConfig } from '@baijanstack/express-auth';

const authConfig: TConfig = {
  BASE_PATH: '/v1/auth', // base path for authentication
  SALT_ROUNDS: 10, // number of rounds for password hashing
  TOKEN_SECRET: 'random_secure_secret_value', // secret for token generation
  ACCESS_TOKEN_AGE: 60000, // age of access token in milliseconds
  REFRESH_TOKEN_AGE: 240000, // age of refresh token in milliseconds
  EMAIL_VERIFICATION_TOKEN_AGE: 300000, // age of email verification token in milliseconds
};
```

- Implement the `INotifyService` for sending notifications.

```ts
import { INotifyService } from '@baijanstack/express-auth';

export class EmailNotificationService implements INotifyService {
  async notify(type: 'TOKEN_STOLEN', email: string): Promise<void> {
    if (type === 'TOKEN_STOLEN') {
      console.log(`Notifying ... ${email}`);
    }
  }
}
```

- Create an instance of the route generator.

You need to pass the `INotifyService` and `TConfig` to the route generator implementations.

```ts
import express from 'express';
import { initAuth, RouteGenerator, TConfig } from '@baijanstack/express-auth';

const app = express();

const routeGenerator = new RouteGenerator(app, notificationService, authConfig);
```

- Initiate the auth library.

```ts
import { initAuth } from '@baijanstack/express-auth';

initAuth({
  routeGenerator,
  signUpHandler: new SignUpHandler(),
  loginHandler: new LoginHandler(),
  logoutHandler: new LogoutHandler(),
  refreshHandler: new RefreshHandler(),
  resetPasswordHandler: new ResetPasswordHandler(),
  meRouteHandler: new MeRouteHandler(),
  verifyEmailHandler: new VerifyEmailHandler(),
  forgotPasswordHandler: new ForgotPasswordHandler(),
  verifyOtpHandler: new VerifyOtpHandler(),
});
```

- When you initiate the auth library, you need to pass handlers for each route. The handlers are independent of storage type - in-memory or database etc.

I will show you how to implement these handlers in the next section using in-memory storage.

> **Note**: You can see an implementation of the handlers using prisma in [Sample Auth Example](https://github.com/baijanathTharu/sample-auth-example).

```ts
import { ISignUpHandler, ILoginHandler, ILogoutHandler, IRefreshHandler, IResetPasswordHandler, IMeRouteHandler, IVerifyEmailHandler, IForgotPasswordHandler, IVerifyOtpHandler } from '@baijanstack/express-auth';

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

  doesUserExists: (body: TSignUpBodyInput) => Promise<boolean> = async (body) => {
    const user = users.find((user) => user.email === body.email);
    return !!user;
  };

  saveUser: (body: TSignUpBodyInput, hashedPassword: string) => Promise<void> = async (body, hashedPassword) => {
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
  saveHashedPassword: (email: string, hashedPassword: string) => Promise<void> = async (email, hashedPassword) => {
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
  getMeByEmail: (email: string) => Promise<{ email: string; name: string } | null> = async (email) => {
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

  isEmailEligibleForVerification: (email: string) => Promise<boolean> = async (email) => {
    const user = users.find((user) => user.email === email);

    return !user?.is_email_verified;
  };

  sendVerificationEmail: (input: { email: string; verificationPath: string }) => Promise<void> = async (input) => {
    console.log('sendVerificationEmail Input', input);
  };
}

export class ForgotPasswordHandler implements IForgotPasswordHandler {
  doesUserExists: (email: string) => Promise<boolean> = async (email) => {
    const user = users.find((user) => user.email === email);
    return !!user;
  };

  saveOtp: (email: string, otp: { code: string; generatedAt: number }) => Promise<void> = async (email, otp) => {
    const userIdx = users.findIndex((user) => user.email === email);
    if (userIdx < 0) {
      throw new Error(`User not found`);
    }
    users[userIdx].otps.push(otp);
  };

  sendOtp: (email: string, otp: { code: string; generatedAt: number }) => Promise<void> = async (email, otp) => {
    console.log('sendOtp', email, otp);
  };
}

export class VerifyOtpHandler implements IVerifyOtpHandler {
  isOtpValid: (email: string, otp: string) => Promise<boolean> = async (email, otp) => {
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

  saveNewPassword: (email: string, password: string) => Promise<void> = async (email, password) => {
    const userIdx = users.findIndex((user) => user.email === email);
    if (userIdx < 0) {
      throw new Error(`User not found`);
    }
    users[userIdx].password = password;
  };
}
```

## Protected Routes

You can protect your routes by using the middlewares provided by this library.

The `routeGenerator` has a middleware to protect your routes.

```ts
app.get('/protected', routerGenerator.validateAccessToken, (req, res) => {
  console.log('Logged in user is:', req.user);
  res.send('Hello World');
});
```

## Collaborators

- [Baijanath Tharu](https://github.com/baijanathTharu)
- [Santosh Kunwar](https://github.com/codemon77)
- [Susan Shakya](https://github.com/susan-shakya1)
