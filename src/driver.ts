/*
|--------------------------------------------------------------------------
| Ally Oauth driver
|--------------------------------------------------------------------------
|
| Make sure you through the code and comments properly and make necessary
| changes as per the requirements of your implementation.
|
*/

/**
 |--------------------------------------------------------------------------
 *  Search keyword "AppleDriver" and replace it with a meaningful name
 |--------------------------------------------------------------------------
 */
import {Oauth2Driver} from '@adonisjs/ally'
import type {HttpContext} from '@adonisjs/core/http'
import type {AllyDriverContract, AllyUserContract, ApiRequestContract, LiteralStringUnion, RedirectRequestContract} from '@adonisjs/ally/types'
// @ts-ignore
import {DateTime} from 'luxon'
import JWKS, {CertSigningKey, JwksClient, RsaSigningKey} from 'jwks-rsa'
import JWT from 'jsonwebtoken'
// @ts-ignore
import {E_OAUTH_MISSING_CODE, E_OAUTH_STATE_MISMATCH} from "@adonisjs/ally/build/src/errors.js";

/**
 *
 * Access token returned by your driver implementation. An access
 * token must have "token" and "type" properties and you may
 * define additional properties (if needed)
 */
export type AppleDriverAccessToken = {
  token: string
  type: string
  id_token: string
  refreshToken: string
  expiresIn: number
  expiresAt: DateTime
}

/**
 * Scopes accepted by the driver implementation.
 */
export type AppleDriverScopes = 'email' | 'string'



export interface AppleUserContract extends Omit<AllyUserContract<AppleDriverAccessToken>, 'token'> {}



/**
 * Shape of the Apple decoded token
 * https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/incorporating_sign_in_with_apple_into_other_platforms
 */
export type AppleTokenDecoded = {
  iss: string
  aud: string
  exp: number
  iat: number
  sub: string
  at_hash: string
  email: string
  email_verified: 'true' | 'false'
  user?: {
    email?: string
    name?: {
      firstName: string
      lastName: string
    }
  }
  is_private_email: boolean
  auth_time: number
  nonce_supported: boolean
}



/**
 *
 * The configuration accepted by the driver implementation.
 */
export type AppleDriverConfig = {
  driver: 'apple'
  appId: string
  teamId: string
  clientId: string
  clientSecret: string
  callbackUrl: string
  scopes?: LiteralStringUnion<AppleDriverScopes>[]
};

/**
 * Driver implementation. It is mostly configuration driven except the API call
 * to get user info.
 */
export class AppleDriver
  extends Oauth2Driver<AppleDriverAccessToken, AppleDriverScopes>
  implements AllyDriverContract<AppleDriverAccessToken, AppleDriverScopes> {
  /**
   * The URL for the redirect request. The user will be redirected on this page
   * to authorize the request.
   *
   * Do not define query strings in this URL.
   */
  protected authorizeUrl = 'https://appleid.apple.com/auth/authorize'

  /**
   * The URL to hit to exchange the authorization code for the access token
   *
   * Do not define query strings in this URL.
   */
  protected accessTokenUrl = 'https://appleid.apple.com/auth/token'

  /**
   * The URL to hit to get the user details
   *
   * Do not define query strings in this URL.
   */
  protected userInfoUrl = ''
  protected jwksClient: JwksClient | null = null

  /**
   * The param name for the authorization code. Read the documentation of your oauth
   * provider and update the param name to match the query string field name in
   * which the oauth provider sends the authorization_code post redirect.
   */
  protected codeParamName = 'code'

  /**
   * The param name for the error. Read the documentation of your oauth provider and update
   * the param name to match the query string field name in which the oauth provider sends
   * the error post redirect
   */
  protected errorParamName = 'error'

  /**
   * Cookie name for storing the CSRF token. Make sure it is always unique. So a better
   * approach is to prefix the oauth provider name to `oauth_state` value. For example:
   * For example: "facebook_oauth_state"
   */
  protected stateCookieName = 'apple_oauth_state'

  /**
   * Parameter name to be used for sending and receiving the state from.
   * Read the documentation of your oauth provider and update the param
   * name to match the query string used by the provider for exchanging
   * the state.
   */
  protected stateParamName = 'state'

  /**
   * Parameter name for sending the scopes to the oauth provider.
   */
  protected scopeParamName = 'scope'

  /**
   * The separator indentifier for defining multiple scopes
   */
  protected scopesSeparator = ' '

  constructor(
    ctx: HttpContext,
    public config: AppleDriverConfig
  ) {
    super(ctx, config)

    this.jwksClient = JWKS({
      rateLimit: true,
      cache: true,
      cacheMaxEntries: 100,
      cacheMaxAge: 1000 * 60 * 60 * 24,
      jwksUri: 'https://appleid.apple.com/auth/keys',
    })
    this.loadState()
  }

  /**
   * Optionally configure the authorization redirect request. The actual request
   * is made by the base implementation of "Oauth2" driver and this is a
   * hook to pre-configure the request.
   */
  protected configureRedirectRequest(request: RedirectRequestContract<AppleDriverScopes>) {
    /**
     * Define user defined scopes or the default one's
     */
    request.scopes(this.config.scopes || ['email'])

    request.param('client_id', this.config.appId)
    request.param('response_type', 'code')
    request.param('response_mode', 'form_post')
    request.param('grant_type', 'authorization_code')
  }


  /**
   * Update the implementation to tell if the error received during redirect
   * means "ACCESS DENIED".
   */
  accessDenied() {
    return this.ctx.request.input('error') === 'user_denied'
  }

  /**
   * Get Apple Signning Keys to verify token
   * @param token an id_token receoived from Apple
   * @returns signing key
   */
  protected async getAppleSigningKey(token: string): Promise<string> {
    const decodedToken = JWT.decode(token, {complete: true})
    const key = await this.jwksClient?.getSigningKey(decodedToken?.header.kid)
    return (key as CertSigningKey)?.publicKey || (key as RsaSigningKey)?.rsaPublicKey
  }
  /**
   * Generates Client Secret
   * https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
   * @returns clientSecret
   */
  protected generateClientSecret(): string {
    const clientSecret = JWT.sign({}, this.config.clientSecret, {
      algorithm: 'ES256',
      keyid: this.config.clientId,
      issuer: this.config.teamId,
      audience: 'https://appleid.apple.com',
      subject: this.config.appId,
      expiresIn: 60,
      header: { alg: 'ES256', kid: this.config.clientId },
    })
    return clientSecret
  }

  protected async getUserInfo(token: string): Promise<AppleUserContract> {
    const signingKey = await this.getAppleSigningKey(token)
    const decodedUser = JWT.verify(token, signingKey, {
      issuer: 'https://appleid.apple.com',
      audience: this.config.appId,
    })
    const firstName = (decodedUser as AppleTokenDecoded)?.user?.name?.firstName || ''
    const lastName = (decodedUser as AppleTokenDecoded)?.user?.name?.lastName || ''

    return {
      id: (decodedUser as AppleTokenDecoded).sub,
      avatarUrl: null,
      original: null,
      nickName: (decodedUser as AppleTokenDecoded).sub,
      name: `${firstName}${lastName ? ` ${lastName}` : ''}`,
      email: (decodedUser as AppleTokenDecoded).email,
      emailVerificationState:
        (decodedUser as AppleTokenDecoded).email_verified === 'true' ? 'verified' : 'unverified',
    }
  }
  /**
   * Get access token
   */
  public async accessToken(
    callback?: (request: ApiRequestContract) => void
  ): Promise<AppleDriverAccessToken> {
    /**
     * We expect the user to handle errors before calling this method
     */
    if (this.hasError()) {
      throw E_OAUTH_MISSING_CODE
    }

    /**
     * We expect the user to properly handle the state mis-match use case before
     * calling this method
     */
    if (this.stateMisMatch()) {
      throw E_OAUTH_STATE_MISMATCH
    }

    return this.getAccessToken((request) => {
      request.header('Content-Type', 'application/x-www-form-urlencoded')
      request.field('client_id', this.config.appId)
      request.field('client_secret', this.generateClientSecret())
      request.field(this.codeParamName, this.getCode())

      if (typeof callback === 'function') {
        callback(request)
      }
    })
  }


  /**
   * Returns details for the authorized user
   */
  public async user(callback?: (request: ApiRequestContract) => void) {
    const token = await this.accessToken(callback)
    const user = await this.getUserInfo(token.id_token)

    return {
      ...user,
      token,
    }
  }
  public async userFromToken(token: string) {
    const user = await this.getUserInfo(token)

    return {
      ...user,
      token: { token, type: 'bearer' as const },
    }
  }
}

/**
 * The factory function to reference the driver implementation
 * inside the "config/ally.ts" file.
 */
export function AppleDriverService(config: AppleDriverConfig): (ctx: HttpContext) => AppleDriver {
  return (ctx) => new AppleDriver(ctx, config)
}
