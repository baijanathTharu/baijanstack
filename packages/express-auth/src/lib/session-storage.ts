import { IStorageManager } from './session-interfaces';

/**
 * This is a implementation of the IStorageManager interface.
 * You can use it to store tokens in memory for token revocations.
 */
export class MemoryStorage implements IStorageManager {
  private store = new Map<string, unknown>();

  get(key: string): Promise<string | null> {
    this.store.entries();

    const item = this.store.get(key);

    /**
     * item must be an object with an expiresAt (number) and a value (string) properties
     */
    if (!item) {
      console.error('item not found', item);
      return Promise.resolve(null);
    }

    if (typeof item !== 'object') {
      console.error('item is not an object', item);
      return Promise.resolve(null);
    }

    if (!('expiresAt' in item)) {
      console.error('item is not an object with expiresAt property', item);
      return Promise.resolve(null);
    }

    if (!('value' in item)) {
      console.error('item is not an object with value property', item);
      return Promise.resolve(null);
    }

    if (typeof item.expiresAt !== 'number') {
      console.error('expiresAt is not a number', item.expiresAt);
      return Promise.resolve(null);
    }

    if (typeof item.value !== 'string') {
      console.error('value is not a string', item.value);
      return Promise.resolve(null);
    }

    if (item.expiresAt > Date.now()) {
      return Promise.resolve(item.value);
    }

    this.store.delete(key);
    return Promise.resolve(null);
  }
  remove(key: string): Promise<void> {
    this.store.delete(key);
    return Promise.resolve();
  }
  set(
    key: string,
    value: string,
    /**
     * Time to live in milliseconds
     */
    ttl: number
  ): Promise<void> {
    this.store.set(key, {
      value,
      expiresAt: ttl ? Date.now() + ttl : null,
    });
    return Promise.resolve();
  }
}
