import { ISessionManager, IStorageManager } from '../interfaces';

// SessionManager.ts
export class SessionManager implements ISessionManager {
  private storage: IStorageManager;

  constructor(storage: IStorageManager) {
    this.storage = storage;
  }

  // Use the storage manager to store a token
  async storeSession(refreshToken: string, deviceInfo: string): Promise<void> {
    const key = `${refreshToken}`;
    await this.storage.set(key, deviceInfo);
  }

  // Use the storage manager to retrieve a token
  async getSession(refreshToken: string): Promise<string | null> {
    const key = `${refreshToken}`;
    return await this.storage.get(key);
  }

  // Use the storage manager to delete a token
  async deleteSession(refreshToken: string): Promise<void> {
    const key = `${refreshToken}`;
    this.storage.remove(key);
  }

  async verifyDevice(
    refreshToken: string,
    deviceInfo: string
  ): Promise<boolean> {
    const deviceInfoRes = await this.getSession(refreshToken);
    if (!deviceInfoRes) {
      return false;
    }
    return deviceInfoRes === deviceInfo;
  }
}
