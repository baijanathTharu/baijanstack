# express-auth

This library generates routes for authentication.

## Usage

1. Install the dependency.

```bash
npm install @baijanstack/express-auth
```

## Descriptions

The routes are as follows:

- [x] **/v1/auth/signup**: This route handles sign up of new user.

- [x] **/v1/auth/login**: This route handles login of user.

- [x] **/v1/auth/logout**: This route log outs user from the application.

- [ ] **/v1/auth/refresh**: This route refreshes the access token.

- [ ] **/v1/auth/verify-email**: This route verifies the email.

- [ ] **/v1/auth/reset-password**: This route resets the password.

This library is independent of data persistence i.e. it is the job of the user to provide the implementation of the data persistence layer. It provides the interface for the persistence layer.

# Important Notes

Following environment variables must be set:

The type of the config is TConfig defined in `@baijanstack/express-auth`

```bash
export SALT_ROUNDS=10
export TOKEN_SECRET=secret
export ACCESS_TOKEN_AGE=900000 # default is 15 minutes
export REFRESH_TOKEN_AGE=6.048e+8 # default is 7 days
```

> Secret can be generated using `openssl`

```bash
openssl rand -base64 32
```
