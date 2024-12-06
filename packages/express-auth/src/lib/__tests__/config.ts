import { TConfig } from '../auth-interfaces';

export const config: TConfig = {
  BASE_PATH: '/v1/auth',
  SALT_ROUNDS: 10,
  TOKEN_SECRET: 'test',
  ACCESS_TOKEN_AGE: 2 * 60 * 1000, // 2 minute
  REFRESH_TOKEN_AGE: 1000 * 60 * 60 * 24 * 7, // 7 days
  OTP_AGE: 30, // 30 seconds
  OTP_SECRET: 'test',
};
