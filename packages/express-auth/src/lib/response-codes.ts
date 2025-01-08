export const SignUpResponseCodes = {
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  USER_ALREADY_EXISTS: 'USER_ALREADY_EXISTS',
  PASSWORD_HASH_ERROR: 'PASSWORD_HASH_ERROR',
  USER_CREATED: 'USER_CREATED',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
} as const;
export type TSignUpResponseCodes = keyof typeof SignUpResponseCodes;

export const LoginResponseCodes = {
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  PASSWORD_OR_EMAIL_INCORRECT: 'PASSWORD_OR_EMAIL_INCORRECT',
  EMAIL_NOT_VERIFIED: 'EMAIL_NOT_VERIFIED',
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
} as const;
export type TLoginResponseCodes = keyof typeof LoginResponseCodes;

export const LogoutResponseCodes = {
  LOGOUT_SUCCESS: 'LOGOUT_SUCCESS',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
} as const;
export type TLogoutResponseCodes = keyof typeof LogoutResponseCodes;

export const ValidateTokenResponseCodes = {
  MISSING_TOKEN: 'MISSING_TOKEN',
  INVALID_TOKEN: 'INVALID_TOKEN',
  EXPIRED_TOKEN: 'EXPIRED_TOKEN',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
} as const;
export type TValidateTokenResponseCodes =
  keyof typeof ValidateTokenResponseCodes;

export const DeviceValidationResponseCodes = {
  MISSING_DEVICE_TOKEN: 'MISSING_DEVICE_TOKEN',
  MISSING_DEVICE_INFO: 'MISSING_DEVICE_INFO',
  DEVICE_VALIDATION_SUCCESS: 'DEVICE_VALIDATION_SUCCESS',
  SESSION_NOT_FOUND: 'SESSION_NOT_FOUND',
  UNAUTHORIZED_DEVICE: 'UNAUTHORIZED_DEVICE',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
};
export type TDeviceValidationResponseCodes =
  keyof typeof DeviceValidationResponseCodes;

export const RefreshResponseCodes = {
  INVALID_PAYLOAD: 'INVALID_PAYLOAD',
  REFRESH_SUCCESS: 'REFRESH_SUCCESS',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
} as const;
export type TRefreshResponseCodes = keyof typeof RefreshResponseCodes;

export const ResetPasswordResponseCodes = {
  INVALID_PAYLOAD: 'INVALID_PAYLOAD',
  RESET_PASSWORD_SUCCESS: 'RESET_PASSWORD_SUCCESS',
  PASSWORD_HASH_ERROR: 'PASSWORD_HASH_ERROR',
  INVALID_OLD_PASSWORD_USERNAME: 'INVALID_OLD_PASSWORD_USERNAME',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
} as const;
export type TResetPasswordResponseCodes =
  keyof typeof ResetPasswordResponseCodes;

export const MeResponseCodes = {
  INVALID_PAYLOAD: 'INVALID_PAYLOAD',
  ME_SUCCESS: 'ME_SUCCESS',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
} as const;
export type TMeResponseCodes = keyof typeof MeResponseCodes;

export const VerifyEmailResponseCodes = {
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  VERIFY_EMAIL_SUCCESS: 'VERIFY_EMAIL_SUCCESS',
  EMAIL_ALREADY_VERIFIED: 'EMAIL_ALREADY_VERIFIED',
  INVALID_OTP: 'INVALID_OTP',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
} as const;
export type TVerifyEmailResponseCodes = keyof typeof VerifyEmailResponseCodes;

export const SendOtpResponseCodes = {
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  SEND_OTP_SUCCESS: 'SEND_OTP_SUCCESS',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
  USER_NOT_FOUND: 'USER_NOT_FOUND',
} as const;
export type TSendOtpResponseCodes = keyof typeof SendOtpResponseCodes;

export const ForgotPasswordResponseCodes = {
  VALIDATION_FAILED: 'VALIDATION_FAILED',
  FORGOT_PASSWORD_SUCCESS: 'FORGOT_PASSWORD_SUCCESS',
  USER_NOT_FOUND: 'USER_NOT_FOUND',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
  PASSWORD_HASH_ERROR: 'PASSWORD_HASH_ERROR',
  INVALID_OTP: 'INVALID_OTP',
} as const;
export type TForgotPasswordResponseCodes =
  keyof typeof ForgotPasswordResponseCodes;
