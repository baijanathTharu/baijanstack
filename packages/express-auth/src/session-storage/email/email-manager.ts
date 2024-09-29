import { IEmailService } from '../interfaces';

class EmailServiceManagerClass {
  private static instance: EmailServiceManagerClass;
  private emailService: IEmailService | null = null;

  private constructor() {
    //
  }
  
  // Singleton instance to manage the email service
  public static getInstance(): EmailServiceManagerClass {
    if (!EmailServiceManagerClass.instance) {
      EmailServiceManagerClass.instance = new EmailServiceManagerClass();
    }
    return EmailServiceManagerClass.instance;
  }

  // Allow the user to register their email service
  public registerEmailService(service: IEmailService): void {
    this.emailService = service;
  }

  // Get the registered email service
  public getEmailService(): IEmailService | null {
    if (!this.emailService) {
      return null;
    }
    return this.emailService;
  }
}

export const EmailServiceManager = EmailServiceManagerClass.getInstance();
