import { Application as ExpressApplication } from 'express';
import {
  AuthProvider,
  IOAuthGenerator,
  IOAuthHandler,
  TConfig,
  TGoogleAuthConfig,
  TGoogleProfile,
} from '../auth-interfaces';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth2';
import { OAuthResponseCodes } from '../response-codes';
import { SessionManager } from '../session-interfaces';
import {
  extractDeviceIdentifier,
  generateTokens,
  setCookies,
} from '../../utils';

export class GoogleAuthGenerator implements IOAuthGenerator {
  constructor(
    private app: ExpressApplication,
    private config: TConfig & TGoogleAuthConfig,
    private oauthHandler: IOAuthHandler,
    private sessionManager?: SessionManager
  ) {
    if (!config.GOOGLE_CLIENT_ID || !config.GOOGLE_CLIENT_SECRET) {
      throw new Error('Google client ID and secret must be provided');
    }
    passport.use(
      new GoogleStrategy(
        {
          clientID: this.config.GOOGLE_CLIENT_ID,
          clientSecret: this.config.GOOGLE_CLIENT_SECRET,
          callbackURL: `${this.config.BASE_PATH}/google/callback`,
          passReqToCallback: true,
        },
        async function (
          req: any,
          accessToken: any,
          refreshToken: any,
          profile: any,
          done: any
        ) {
          try {
            const googleProfile = {
              id: profile.id,
              displayName: profile.displayName,
              emails:
                profile.emails?.map((e: any) => ({
                  value: e.value,
                  verified: e.verified,
                })) || [],
              photos: profile.photos || [],
              _json: profile._json || null,
            };

            const email = googleProfile.emails[0]?.value;
            if (!email) {
              return done(new Error('No email found in Google profile'), null);
            }

            req.user = {
              email: email,
              displayName: googleProfile.displayName,
              id: googleProfile.id,
            } as TGoogleProfile;

            await oauthHandler.createOrUpdateUser({
              email: email,
              provider: AuthProvider.GOOGLE,
              googleId: googleProfile.id,
              displayName: googleProfile.displayName,
            });

            return done(null, profile);
          } catch (error) {
            console.error('Error creating or updating user:', error);
            return done(error, null);
          }
        }
      )
    );
  }

  createOAuthRoute: (provider: AuthProvider) => ExpressApplication = () => {
    this.app.get(
      `${this.config.BASE_PATH}/google`,
      passport.authenticate('google', {
        scope: ['email', 'profile'],
        successRedirect: `${this.config.BASE_PATH}/google/callback`,
        failureRedirect: this.config.GOOGLE_FAILURE_REDIRECT_URI,
        session: false,
      })
    );

    return this.app.get(
      `${this.config.BASE_PATH}/google/callback`,
      passport.authenticate('google', {
        scope: ['email', 'profile'],
        failureRedirect: this.config.GOOGLE_FAILURE_REDIRECT_URI,
        // successRedirect: this.config.GOOGLE_SUCCESS_REDIRECT_URI,
        session: false,
      }),
      async (req, res) => {
        try {
          const user = req.user as TGoogleProfile;

          if (!user) {
            res.status(401).json({
              message: 'Authentication failed',
              code: OAuthResponseCodes.OAUTH_FAILURE,
            });
            return;
          }

          /**
           * Generate tokens for the user
           */

          const payload = await this.oauthHandler.getTokenPayload(user.email);
          if (!payload) {
            res.status(400).json({
              message: 'Invalid user payload for token generation',
              code: OAuthResponseCodes.OAUTH_FAILURE,
            });
            return;
          }

          const tokens = generateTokens(payload, {
            tokenSecret: this.config?.TOKEN_SECRET ?? '',
            ACCESS_TOKEN_AGE: this.config.ACCESS_TOKEN_AGE,
            REFRESH_TOKEN_AGE: this.config.REFRESH_TOKEN_AGE,
          });

          const deviceInfo = extractDeviceIdentifier(req);

          if (this.sessionManager) {
            this.sessionManager.storeSession(
              tokens.refreshToken,
              req.body.email,
              deviceInfo,
              this.config.REFRESH_TOKEN_AGE * 1000
            );
          }

          setCookies({
            res,
            cookieData: [
              {
                cookieName: 'x-access-token',
                cookieValue: tokens.accessToken,
                maxAge: this.config.ACCESS_TOKEN_AGE * 1000,
                domain: this.config.COOKIE_DOMAIN,
              },
              {
                cookieName: 'x-refresh-token',
                cookieValue: tokens.refreshToken,
                maxAge: this.config.REFRESH_TOKEN_AGE * 1000,
                domain: this.config.COOKIE_DOMAIN,
              },
            ],
          });

          res.redirect(this.config.GOOGLE_SUCCESS_REDIRECT_URI);

          return;
        } catch (error) {
          console.error(`Error during Google OAuth callback:`, error);
          res.status(500).json({
            message: 'Internal server error',
            code: OAuthResponseCodes.INTERNAL_SERVER_ERROR,
          });
          return;
        }
      }
    );
  };
}
