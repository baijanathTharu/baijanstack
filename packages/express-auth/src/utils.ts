import { Response } from 'express';
import { compare, genSalt, hash } from 'bcryptjs';
import { sign, verify } from 'jsonwebtoken';

export function hashPassword(
  password: string,
  saltRounds: number
): Promise<[Error | null, string | null]> {
  return new Promise((resolve, reject) => {
    genSalt(saltRounds, (err, salt) => {
      if (err) {
        console.error(err);
        reject([err, null]);
      }
      hash(password, salt, (hashErr, hashedPassword) => {
        if (hashErr) {
          console.error(hashErr);
          reject([hashErr, null]);
        }
        resolve([null, hashedPassword]);
      });
    });
  });
}

export function comparePassword({
  password,
  hashedPassword,
}: {
  password: string;
  hashedPassword: string;
}): Promise<[Error | null, boolean]> {
  return new Promise((resolve, reject) => {
    compare(password, hashedPassword, (err, result) => {
      if (err) {
        console.error(err);
        reject([err, null]);
      }
      resolve([null, result]);
    });
  });
}

export function generateTokens(
  payload: any,
  {
    ACCESS_TOKEN_AGE,
    REFRESH_TOKEN_AGE,
    tokenSecret,
  }: {
    ACCESS_TOKEN_AGE: number;
    REFRESH_TOKEN_AGE: number;
    tokenSecret: string;
  }
): {
  accessToken: string;
  refreshToken: string;
} {
  const accessToken = sign(payload, tokenSecret, {
    expiresIn: ACCESS_TOKEN_AGE || '15m',
  });
  const refreshToken = sign(payload, tokenSecret, {
    expiresIn: REFRESH_TOKEN_AGE || '7d',
  });
  return {
    accessToken,
    refreshToken,
  };
}

// verify token
export function verifyToken({
  token,
  tokenSecret,
}: {
  token: string;
  tokenSecret: string;
}) {
  try {
    const decoded = verify(token, tokenSecret);
    return decoded;
  } catch (error) {
    console.error('token verification error', error);
    return false;
  }
}

export function setCookies({
  res,
  cookieData,
}: {
  res: Response;
  cookieData: Array<{
    cookieName: string;
    cookieValue: string;
    maxAge: number;
  }>;
}) {
  for (const cookie of cookieData) {
    res.cookie(cookie.cookieName, cookie.cookieValue, {
      path: '/',
      maxAge: cookie.maxAge,
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env['NODE_ENV'] === 'production',
    });
  }
}

export function getTokenValueCookie(cookie: string, cookieName: string) {
  /**
   * Example token
   * x-access-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCIsImVtYWlsIjoidGVzdEB0ZXN0LmNvbSIsImlhdCI6MTcyNjU4OTAwOSwiZXhwIjoxNzI2NTg5OTA5fQ.4_JBB-Qg6Cfop_wP0QoTUi6KGDpaqqkjPeFS3Fd1gz4; Max-Age=900; Path=/; Expires=Tue, 17 Sep 2024 16:18:29 GMT; HttpOnly; SameSite=Lax; x-refresh-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidGVzdCIsImVtYWlsIjoidGVzdEB0ZXN0LmNvbSIsImlhdCI6MTcyNjU4OTAwOSwiZXhwIjoxNzI3MTkzODA5fQ.bEphhPRnuh5ZGhSCD2XODhAh7ycT14sGgvodmg2SH7E; Max-Age=604800; Path=/; Expires=Tue, 24 Sep 2024 16:03:29 GMT; HttpOnly; SameSite=Lax
   */

  const splitted = cookie.split(`${cookieName}=`)[1]?.split(';');

  return splitted?.length ? splitted[0] : '';
}
