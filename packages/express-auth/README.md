# express-auth

This library generates routes for authentication.

The routes are as follows:

- **/v1/auth/signup**: This route handles sign up of new user.

- **/v1/auth/login**: This route handles login of user.

- **/v1/auth/logout**: This route log outs user from the application.

This library is independent of data persistence i.e. it is the job of the user to provide the implementation of the data persistence layer. It provides the interface for the persistence layer.

# Important Notes

Following environment variables must be set:

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
