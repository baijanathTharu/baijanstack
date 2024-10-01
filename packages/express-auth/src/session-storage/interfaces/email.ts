export interface INotifyService {
  notify(type: 'TOKEN_STOLEN', email: string): Promise<void>;
}
