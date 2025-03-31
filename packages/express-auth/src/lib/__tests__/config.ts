import { TConfig } from '../auth-interfaces';

export const config: TConfig = {
  BASE_PATH: '/v1/auth',
  SALT_ROUNDS: 10,
  TOKEN_SECRET: 'test',
  ACCESS_TOKEN_AGE: 2 * 1000, // 2 seconds
  REFRESH_TOKEN_AGE: 2 * 1000, // 2 seconds
  OTP_AGE: 30, // 30 seconds
  OTP_SECRET: 'test',
};
