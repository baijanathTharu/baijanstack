# express-auth

> ! This library is under active development. Please do not use it in production.

This library generates routes for authentication.

## Usage

1. Install the dependency.

```bash
npm install @baijanstack/express-auth@0.0.0-alpha.24
```

## Description

This library uses email-password authentication flow for authentication. It generates routes for authentication and provides the interface for the persistence layer. It uses access token and refresh token for authentication. The tokens are stored in cookies.

The routes are as follows:

- [x] **/v1/auth/signup**: This route handles sign up of new user.

- [x] **/v1/auth/login**: This route handles login of user.

- [x] **/v1/auth/logout**: This route log outs user from the application.

- [x] **/v1/auth/refresh**: This route refreshes the access token.

- [x] **/v1/auth/me**: This route returns the details of logged in user.

- [x] **/v1/auth/reset-password**: This route resets the password of the logged in user.

- [ ] **/v1/auth/forgot-password**: This route sends the link to reset the password.

- [ ] **/v1/auth/verify-email**: This route verifies the email.

# Important Notes

Following environment variables must be set:

The type of the config is TConfig defined in `@baijanstack/express-auth`

```bash
SALT_ROUNDS=10 # Salt rounds to use for password hashing
TOKEN_SECRET=random_secure_secret_value # Token secret to use
ACCESS_TOKEN_AGE=60000 # Access token age in milliseconds
REFRESH_TOKEN_AGE=240000 # Refresh token age in milliseconds
ACCESS_TOKEN_COOKIE_MAX_AGE=60 # Access token cookie max age in seconds
REFRESH_TOKEN_COOKIE_MAX_AGE=86400 # Refresh token cookie max age in seconds
```

## Example

Below is an example of how to use this library.

[Sample Auth Example](https://github.com/baijanathTharu/sample-auth-example)

[Repo Link](https://github.com/baijanathTharu/baijanstack/tree/main/packages/express-auth)

## how to use Session Manager to store session and track device info

```javascript

##index.js

import express from 'express';
import { MyNotifyService } from '../services/email-service';
import { RouteGenerator  } from '@baijanstack/express-auth';

const app = express();

const notifyService = new MyNotifyService();

const routeGenerator = new RouteGenerator(app, notifyService);

const validateSessionDeviceMiddleware = routeGenerator.validateSessionDeviceInfo.bind(routeGenerator);

// sign up route
const signUpPersistor = new SignUpPersistor();
routeGenerator.createSignUpRoute(signUpPersistor);

// login route
const loginPersistor = new LoginPersistor();
routeGenerator.createLoginRoute(loginPersistor);

app.get('/v1/post/:postId', validateSessionDeviceMiddleware, (req, res) => {
  //
});


## services/email-service

import { INotifyService } from '@baijanstack/express-auth';

export class MyNotifyService implements INotifyService {
  async notify(type: 'TOKEN_STOLEN', email: string): Promise<void> {
    if (type === 'TOKEN_STOLEN') {
      console.log(`Notifying ... ${email}`);
    }
  }
}

```
