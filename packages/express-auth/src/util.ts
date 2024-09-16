import { writeFile } from 'fs';
import { join } from 'path';

export async function writeTestLogToFile(text: string) {
  return new Promise((resolve, reject) => {
    writeFile(join(process.cwd(), 'dist/test.log'), text, (err) => {
      if (err) {
        reject(err);
        return;
      }

      resolve(text);
    });
  });
}
