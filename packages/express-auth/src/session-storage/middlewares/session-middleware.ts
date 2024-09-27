// sessionMiddleware.ts
import { Request, Response, NextFunction } from 'express';
import { extractDeviceIdentifier } from '../../utils';
import { ISessionManager } from '../interfaces';

// Middleware factory function
export const createTokenVerificationMiddleware = (
  sessionManager: ISessionManager
) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Skip verification for signup and login routes
    if (req.path === '/v1/auth/signup' || req.path === '/v1/auth/login') {
      return next();
    }

    const refreshToken = req.cookies['x-refresh-token'];
    const deviceInfo = extractDeviceIdentifier(req);

    if (!refreshToken) {
      return res.status(400).send('Missing required authentication data');
    }

    if (!deviceInfo) {
      return res.status(403).send('Unauthorized: Missing device info');
    }

    try {
      const isValidDevice = await sessionManager.verifyDevice(
        refreshToken,
        deviceInfo
      );

      if (!isValidDevice) {
        return res
          .status(401)
          .send('Unauthorized: Invalid device or compromised token.');
      }

      next();
    } catch (error) {
      return res
        .status(500)
        .send('Internal server error during authentication');
    }
  };
};
