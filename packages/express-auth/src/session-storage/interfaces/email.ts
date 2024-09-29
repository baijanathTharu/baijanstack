export interface IEmailService {
  sendEmail(
    to: string,
    subject: string,
    text: string,
    html?: string
  ): Promise<void>;
}
