import { INotifyService } from '../session-interfaces';

export class EmailNotificationService implements INotifyService {
  async sendTokenStolen(email: string): Promise<void> {
    console.log(`Notifying | TOKEN_STOLEN | Email: ${email}`);
  }
  async sendOtp(
    email: string,
    payload: { code: string; generatedAt: number }
  ): Promise<void> {
    console.log(`Notifying | OTP | Email: ${email}`, payload);
  }
  async notifyEmailVerified(email: string): Promise<void> {
    console.log(`Notifying | EMAIL_VERIFIED | Email: ${email}`);
  }
}
