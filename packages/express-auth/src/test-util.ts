import { appendFile } from 'fs';
import { join } from 'path';

export async function writeTestLogToFile(text: string) {
  return new Promise((resolve, reject) => {
    appendFile(
      join(process.cwd(), 'dist/test.log'),
      `\ntime: ${new Date()} | text: ${text}`,
      (err) => {
        if (err) {
          reject(err);
          return;
        }

        resolve(text);
      }
    );
  });
}
