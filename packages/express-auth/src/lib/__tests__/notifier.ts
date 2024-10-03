import { INotifyService } from '../session-interfaces';

export class EmailNotificationService implements INotifyService {
  async notify(type: 'TOKEN_STOLEN', email: string): Promise<void> {
    if (type === 'TOKEN_STOLEN') {
      console.log(`Notifying ... ${email}`);
    }
  }
}
