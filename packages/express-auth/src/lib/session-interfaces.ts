/**
 * This is a interface for the SessionManager
 * It is used to interact with the session storage.
 */
export interface ISessionManager {
  /**
   * Use the storage manager to store a token
   */
  storeSession(
    refreshToken: string,
    userEmail: string,
    deviceInfo: string,
    /**
     * Time to live in milliseconds
     */
    ttlInMs: number
  ): Promise<void>;

  /**
   * Get the session from storage
   */
  getSession(refreshToken: string, deviceInfo: string): Promise<string | null>;

  /**
   * Delete the session from storage
   */
  deleteSession(refreshToken: string): Promise<void>;

  /**
   * Verify the device info in the session
   */
  verifyDevice(refreshToken: string, deviceInfo: string): Promise<boolean>;

  /**
   * Get the email from the session
   */
  getEmailFromSession(refreshToken: string): Promise<string | null>;
}

export interface IStorageManager {
  /**
   * Set the session in storage
   */
  set(key: string, value: string, ttlInMs: number): Promise<void>;

  /**
   * Get the session from storage
   */
  get(key: string): Promise<string | null>;

  /**
   * Delete the session from storage
   */
  remove(key: string): Promise<void>;
}

/**
 * This is a interface for the notify service
 * It is used to send notifications
 */
export interface INotifyService {
  /**
   * Send a notification to the user informing about stolen token
   */
  sendTokenStolen(email: string): Promise<void>;

  /**
   * Send otp to the user
   */
  sendOtp(
    email: string,
    payload: {
      code: string;
    }
  ): Promise<void>;

  notifyEmailVerified(email: string): Promise<void>;
}

export class SessionManager implements ISessionManager {
  private storage: IStorageManager;

  constructor(storage: IStorageManager) {
    this.storage = storage;
  }

  async storeSession(
    refreshToken: string,
    userEmail: string,
    deviceInfo: string,
    ttlInMs: number
  ): Promise<void> {
    const key = `${refreshToken}`;
    const value = `${userEmail}:${deviceInfo}`;
    await this.storage.set(key, value, ttlInMs);
  }

  async getSession(refreshToken: string): Promise<string | null> {
    const key = `${refreshToken}`;
    return await this.storage.get(key);
  }

  async deleteSession(refreshToken: string): Promise<void> {
    const key = `${refreshToken}`;
    this.storage.remove(key);
  }

  async verifyDevice(
    refreshToken: string,
    deviceInfo: string
  ): Promise<boolean> {
    const value = await this.getSession(refreshToken);
    if (!value) {
      return false;
    }

    const deviceInfoRes = value.split(':')[1];
    return deviceInfoRes === deviceInfo;
  }
  async getEmailFromSession(refreshToken: string): Promise<string | null> {
    const value = await this.getSession(refreshToken);
    if (!value) {
      return null;
    }
    const userEmail = value.split(':')[0];
    return userEmail;
  }
}
