import { createClient } from 'redis';
import { IStorageManager } from '../interfaces';

export class RedisStorage implements IStorageManager {
  private client: ReturnType<typeof createClient>;

  constructor(redisUrl: string) {
    this.client = createClient({ url: redisUrl });

    this.client.connect().then((err) => {
      console.error('Failed to connect to Redis:', err);
    });

    this.client.on('error', (err) => {
      console.error('Redis error:', err);
    });
  }
  get(key: string): Promise<string | null> {
    return this.client.get(key);
  }
  async remove(key: string): Promise<void> {
    await this.client.del(key);
  }
  async set(key: string, value: string, ttl?: number): Promise<void> {
    const expiresAt = ttl ? Date.now() + ttl : 60 * 60 * 24 * 7;
    await this.client.set(key, value, {
      EX: expiresAt,
    });
  }
}
