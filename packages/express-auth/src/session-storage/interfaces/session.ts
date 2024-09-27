// StorageManager Interface
export interface ISessionManager {
  storeSession(refreshToken: string, deviceInfo: string): Promise<void>;
  getSession(refreshToken: string, deviceInfo: string): Promise<string | null>;
  deleteSession(refreshToken: string): Promise<void>;
  verifyDevice(refreshToken: string, deviceInfo: string): Promise<boolean>;
}