import dotenv from 'dotenv';

dotenv.config({
  path: '.env',
});

import { TConfig, TGoogleAuthConfig } from '../auth-interfaces';

export const config: TConfig = {
  BASE_PATH: '/v1/auth',
  SALT_ROUNDS: 10,
  TOKEN_SECRET: 'test',
  ACCESS_TOKEN_AGE: 15, // 15 seconds
  REFRESH_TOKEN_AGE: 300, // 5 minutes
  OTP_AGE: 30, // 30 seconds
  OTP_SECRET: 'test',
  TEST_OTP: '123456', // 6 digits
};

export const googleConfig: TGoogleAuthConfig = {
  GOOGLE_CLIENT_ID: process.env['GOOGLE_CLIENT_ID'] || 'test-client-id',
  GOOGLE_CLIENT_SECRET:
    process.env['GOOGLE_CLIENT_SECRET'] || 'test-client-secret',
  GOOGLE_FAILURE_REDIRECT_URI: '/v1/auth/google/failure',
  GOOGLE_SUCCESS_REDIRECT_URI: '/protected',
};
