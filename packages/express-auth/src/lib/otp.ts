import { totp } from 'otplib';

export interface IOTPService {
  generateOtp: (secret: string) => string;
  verifyOtp: (otp: string, secret: string) => boolean;
}

export class OTPService implements IOTPService {
  private static _instance: OTPService;

  static getInstance(options: { step: number }) {
    if (!OTPService._instance) {
      OTPService._instance = new OTPService(options);
    }
    return OTPService._instance;
  }

  _totp: typeof totp = totp;

  private constructor(options: {
    step: number; // seconds
  }) {
    this._totp.options = {
      step: options.step,
    };
  }

  /**
   * This function generates an OTP.
   */
  generateOtp(secret: string) {
    const otp = this._totp.generate(secret);
    return otp;
  }

  /**
   * This function verifies the OTP.
   */
  verifyOtp(
    /**
     * The otp
     */
    otp: string,
    /**
     * The secret used to generate the otp
     */
    secret: string
  ) {
    try {
      const isValid = this._totp.check(otp, secret);
      return isValid;
    } catch (error) {
      console.error('Failed to verify the otp:', error);
      return false;
    }
  }
}
