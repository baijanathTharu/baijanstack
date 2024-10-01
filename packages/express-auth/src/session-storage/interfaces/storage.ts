// StorageManager Interface
export interface IStorageManager {
  set(key: string, value: string, ttl?: number): Promise<void>;
  get(key: string): Promise<string | null>;
  remove(key: string): Promise<void>;
}
