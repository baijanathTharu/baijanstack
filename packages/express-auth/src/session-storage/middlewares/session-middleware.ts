import { Request, Response, NextFunction } from 'express';
import { extractDeviceIdentifier } from '../../utils';
import { ISessionManager } from '../interfaces';
import { EmailServiceManager } from '../email/email-manager';

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
      const userEmail = await sessionManager.getEmailFromSession(refreshToken);

      if (!isValidDevice) {
        const emailService = EmailServiceManager.getEmailService();

        if (emailService && userEmail) {
          // email will be sent in background
          emailService.sendEmail(
            userEmail,
            'Unauthorized Access Attempt',
            'Someone tried to access your account from an unauthorized device. You have been logged out for security.'
          );
        }

        res.clearCookie('x-refresh-token');
        res.clearCookie('x-access-token');
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
