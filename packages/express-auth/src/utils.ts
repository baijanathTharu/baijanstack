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
        reject([err, null]);
      }
      hash(password, salt, (hashErr, hashedPassword) => {
        if (hashErr) {
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
    ACCESS_TOKEN_AGE: string;
    REFRESH_TOKEN_AGE: string;
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
export async function verifyToken({
  token,
  tokenSecret,
}: {
  token: string;
  tokenSecret: string;
}) {
  try {
    const decodedAccessToken = verify(token, tokenSecret) as {
      userId: number;
    };

    return {
      userId: decodedAccessToken.userId,
    };
  } catch (error) {
    console.log(error);
    return { userId: null };
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
