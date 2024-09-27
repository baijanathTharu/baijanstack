# express-auth

> ! This library is under active development. Please do not use it in production.

This library generates routes for authentication.

## Usage

1. Install the dependency.

```bash
npm install @baijanstack/express-auth@0.0.0-alpha.20
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
SALT_ROUNDS=10
TOKEN_SECRET=random_secure_secret_value
ACCESS_TOKEN_AGE=60000
REFRESH_TOKEN_AGE=240000
ACCESS_TOKEN_COOKIE_MAX_AGE=60
REFRESH_TOKEN_COOKIE_MAX_AGE=86400
```

## Example

Below is an example of how to use this library.

[Sample Auth Example](https://github.com/baijanathTharu/sample-auth-example)

[Repo Link](https://github.com/baijanathTharu/baijanstack/tree/main/packages/express-auth)


## how to use Session Manager to store session and track device info

```javascript
import express from 'express';
import { MemoryStorage, RedisStorage, SessionManager , createTokenVerificationMiddleware } from '@baijanstack/express-auth';

const app = express();

// Choose the storage type (e.g., memory storage)
const storage = new MemoryStorage(); 

/**
 * If you want to you redis for storage 
 * const storage = new RedisStorage("redis:localhost:6379");
 **/


const session = new SessionManager(storage);

app.use( createTokenVerificationMiddleware(session)); //  Verifies user tokens and user device .

const routeGenerator = new RouteGenerator(app,session);

```
