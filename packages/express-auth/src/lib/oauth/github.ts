import {
  AuthProvider,
  IOAuthGenerator,
  IOAuthHandler,
  TConfig,
  TGithubAuthConfig,
  TGithubProfile,
} from '../auth-interfaces';
import { Application as ExpressApplication } from 'express';
import { SessionManager } from '../session-interfaces';
import passport from 'passport';
import { Strategy as GitHubStrategy } from 'passport-github';
import { OAuthResponseCodes } from '../response-codes';
import {
  extractDeviceIdentifier,
  generateTokens,
  setCookies,
} from '../../utils';

export class GithubAuthGenerator implements IOAuthGenerator {
  constructor(
    private app: ExpressApplication,
    private config: TConfig & TGithubAuthConfig,
    private oauthHandler: IOAuthHandler,
    private sessionManager?: SessionManager
  ) {
    if (!config.GITHUB_CLIENT_ID || !config.GITHUB_CLIENT_SECRET) {
      throw new Error('Github client ID and secret must be provided');
    }
    passport.use(
      new GitHubStrategy(
        {
          clientID: this.config.GITHUB_CLIENT_ID,
          clientSecret: this.config.GITHUB_CLIENT_SECRET,
          callbackURL: `${this.config.BASE_PATH}/github/callback`,
          passReqToCallback: true,
        },
        async function (req: any, profile: any, done: any) {
          try {
            console.log(req);
            const githubProfile = {
              id: profile.id,
              displayName: profile.displayName,
              emails:
                profile.emails?.map((e: any) => ({
                  value: e.value,
                  verfied: e.verfied,
                })) || [],
              photos: profile.photoes || [],
              _json: profile._json || null,
            };

            const email = githubProfile.emails[0]?.value;
            if (!email) {
              return done(new Error('No email found in Github profile'), null);
            }

            req.user = {
              id: githubProfile.id,
              email: email,
              displayName: githubProfile.displayName,
            } as TGithubProfile;

            await oauthHandler.createOrUpdateUser({
              email: email,
              provider: AuthProvider.GITHUB,
              providerId: githubProfile.id,
              displayName: githubProfile.displayName,
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
      `${this.config.BASE_PATH}/github`,
      passport.authenticate('github', {
        scope: ['email', 'profile'],
        successRedirect: `${this.config.BASE_PATH}/github/callback`,
        failureRedirect: this.config.GITHUB_FAILURE_REDIRECT_URI,
        session: false,
      })
    );

    return this.app.get(
      `${this.config.BASE_PATH}/github/callback`,
      passport.authenticate('github', {
        scope: ['email', 'profile'],
        failureRedirect: this.config.GITHUB_FAILURE_REDIRECT_URI,
        session: false,
      }),
      async (req, res) => {
        try {
          const user = req.user as TGithubProfile;

          if (!user) {
            res.status(401).json({
              message: 'Authentication failed',
              code: OAuthResponseCodes.OAUTH_FAILURE,
            });
            return;
          }

          const payload = await this.oauthHandler.getTokenPayload(user.email);
          if (!payload) {
            res.status(400).json({
              message: 'Invalid user payload for token generation',
              code: OAuthResponseCodes.OAUTH_FAILURE,
            });
            return;
          }

          const tokens = generateTokens(payload, {
            tokenSecret: this.config.TOKEN_SECRET ?? '',
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
              },
              {
                cookieName: 'x-refresh-token',
                cookieValue: tokens.refreshToken,
                maxAge: this.config.REFRESH_TOKEN_AGE * 1000,
              },
            ],
          });

          res.redirect(this.config.GITHUB_SUCCESS_REDIRECT_URI);

          return;
        } catch (error) {
          console.error('Error during Github OAuth callback:', error);
          res.status(500).json({
            message: 'Internal server error',
            code: OAuthResponseCodes.INTERNAL_SERVER_ERROR,
          });
        }
      }
    );
  };
}
