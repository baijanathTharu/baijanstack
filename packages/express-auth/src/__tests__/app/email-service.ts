import { INotifyService } from '../../session-storage';

export class MyNotifyService implements INotifyService {
  async notify(type: 'TOKEN_STOLEN', email: string): Promise<void> {
    if (type === 'TOKEN_STOLEN') {
      console.log('Notification : Email sent to ' + email);
    }
  }
}
