# express-auth

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

### POST /signup

This route handles sign up of new user.

> Request Body must have email and password properties:

## Request

```json
{
  "email": "baijan@test.com",
  "password": "baijan",
  "name": "baijan"
}
```

## Response

```ts
{
  message: string;
  code: TSignUpResponseCodes;
}
```

When you sign up, we will hash the password and \*send the email for verification. We will store the hashed password in the storage using the implementation provided.

### POST /verify-email

This route is used to verify the email after signing up.

> Note: Before making request to this route, you need to make a request to `/send-otp` route to send the OTP.

## Request

> Request Body must have email and otp properties:

```json
{
  "email": "baijan@test.com",
  "otp": "123456"
}
```

## Response

```ts
{
  message: string;
  code: TVerifyEmailResponseCodes;
}
```

### POST /login

This route handles login of user.

> Request Body must have email and password properties:

## Request

```json
{
  "email": "baijan@test.com",
  "password": "baijan"
}
```

## Response

> Note: user will be type of user you return from your handler

```ts
{
  message: string;
  code: TLoginResponseCodes;
  data: {
    accessToken: string;
    refreshToken: string;
    user: any;
  }
}
```

### POST /logout

This route log outs user from the application. We will invalidate the refresh token.

## Response

```ts
{
  message: string;
  code: TLogoutResponseCodes;
}
```

### POST /refresh

This route refreshes the access token and refresh token if refresh token is valid.

## Response

```ts
{
  message: string;
  code: TRefreshResponseCodes;
}
```

### GET /me

This route returns the details of logged in user.

## Response

```ts
{
  message: string;
  code: TMeResponseCodes;
  accessToken: string;
  data: {
    me: any; // data of logged in user: name, email
    token: {
      name: string;
      email: string;
      iat: number;
      exp: number;
    }
  }
}
```

### POST /reset

This route resets the password of the logged in user.

## Request

```json
{
  "oldPassword": "old_password",
  "newPassword": "new_password"
}
```

## Response

```ts
{
  message: string;
  code: TResetPasswordResponseCodes;
}
```

### POST /forgot-password

This route is used to change the password of the logged out user.

> Note: Before making request to this route, you need to make a request to `/send-otp` route to get the OTP.

> Request Body must have email property:

## Request

```json
{
  "email": "baijan@test.com",
  "otp": "123456",
  "newPassword": "new_password"
}
```

## Response

```ts
{
  message: string;
  code: TForgotPasswordResponseCodes;
}
```

### POST /send-otp

This route is used to get an OTP for verification. [otplib](https://www.npmjs.com/package/otplib) is used to generate the OTP.

> Request Body must have email property:

## Request

```json
{
  "email": "baijan@test.com"
}
```

## Response

```ts
{
  message: string;
  code: TSendOtpResponseCodes;
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
  ACCESS_TOKEN_AGE: 60, // age of access token in seconds
  REFRESH_TOKEN_AGE: 240000, // age of refresh token in seconds
  OTP_AGE: 30, // age/step of otp in seconds
  OTP_SECRET: 'random_secure_secret_value', // secret for otp generation
};
```

- Implement the `INotifyService` for sending notifications. We will use `EmailNotificationService` for sending notifications for different events such as `TOKEN_STOLEN`, `OTP` and `EMAIL_VERIFIED`.

```ts
// notifier.ts
import { INotifyService } from '@baijanstack/express-auth';

export class EmailNotificationService implements INotifyService {
  async sendTokenStolen(email: string): Promise<void> {
    console.log(`Notifying | TOKEN_STOLEN | Email: ${email}`);
  }
  async sendOtp(email: string, payload: { code: string; generatedAt: number }): Promise<void> {
    console.log(`Notifying | OTP | Email: ${email}`, payload);
  }
  async notifyEmailVerified(email: string): Promise<void> {
    console.log(`Notifying | EMAIL_VERIFIED | Email: ${email}`);
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
  // ... need to import all the handlers from
  // `handlers.ts` file that we will make in next section
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

> **Note**: You can see an implementation of the handlers in the [Test file](https://github.com/baijanathTharu/baijanstack/blob/main/packages/express-auth/src/lib/__tests__/handlers.ts).

### In-memory handlers

```ts
// handlers.ts
import { ISignUpHandler, ILoginHandler, ILogoutHandler, IRefreshHandler, IResetPasswordHandler, IMeRouteHandler, IVerifyEmailHandler, IForgotPasswordHandler, ISendOtpHandler } from '@baijanstack/express-auth';

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

  doesUserExists: (body: TSignUpBodyInput) => Promise<boolean> = async (body) => {
    const user = users.find((user) => user.email === body.email);
    return !!user;
  };

  saveUser: (body: TSignUpBodyInput, hashedPassword: string) => Promise<void> = async (body, hashedPassword) => {
    users.push({
      name: body.name,
      email: body.email,
      password: hashedPassword,
      /**
       * !!for testing...
       */
      is_email_verified: true,
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
  isEmailAlreadyVerified: (email: string) => Promise<boolean> = async (email) => {
    const user = users.find((user) => user.email === email);

    return !user?.is_email_verified;
  };

  updateIsEmailVerifiedField: (email: string) => Promise<void> = async (email) => {
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

You can protect your routes by using the middleware `validateAccesstoken` provided by this library.

Note: You can send the tokens either from the cookie or in headers. Please make sure you are not adding `Bearer` before the token else you will get invalid token error. If you are using headers, you must send token as below:

```
x-access-token: <token_value>
x-refresh-token: <token_value>
```

```ts
import { validateAccessToken } from 'baijanstack/express-auth';

app.get('/protected', validateAccessToken, (req, res) => {
  console.log('Logged in user is:', req.user);
  res.send('Hello World');
});
```

> Note: If the middlewares return response, they are in following format:

### Middlewares: `validateAccessToken`, `validateRefreshToken`

```ts
{
  message: string;
  code: TValidateTokenResponseCodes;
}
```

## Collaborators

- [Baijanath Tharu](https://github.com/baijanathTharu)
- [Santosh Kunwar](https://github.com/codemon77)
- [Susan Shakya](https://github.com/susan-shakya1)
