import { IStorageManager } from '../interfaces';

export class MemoryStorage implements IStorageManager {
  private store = new Map<string, any>();

  get(key: string): Promise<string | null> {
    const token = this.store.entries();
    console.log(token);

    const item = this.store.get(key);
    if (item && (item.expiresAt === null || item.expiresAt > Date.now())) {
      return Promise.resolve(item.value);
    }
    this.store.delete(key);
    return Promise.resolve(null);
  }
  remove(key: string): Promise<void> {
    this.store.delete(key);
    return Promise.resolve();
  }
  set(key: string, value: string, ttl?: number): Promise<void> {
    this.store.set(key, {
      value,
      expiresAt: ttl ? Date.now() + ttl : null,
    });
    return Promise.resolve();
  }
}
