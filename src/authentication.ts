/**
 * Authentication module for the Postmancer MCP server
 * Provides handlers for different authentication methods
 */

import { z } from 'zod';
import crypto from 'crypto';
import logger from './logger.js';
import { AuthenticationError } from './errors.js';

// Base authentication schema
export const BaseAuthSchema = z.object({
  type: z.string(),
});

// OAuth2 flow types
export const OAuth2FlowSchema = z.enum(['authorization_code', 'client_credentials', 'password', 'implicit']);

// Basic authentication (username/password)
export const BasicAuthSchema = BaseAuthSchema.extend({
  type: z.literal('basic'),
  username: z.string(),
  password: z.string(),
});

// Bearer token authentication
export const BearerAuthSchema = BaseAuthSchema.extend({
  type: z.literal('bearer'),
  token: z.string(),
});

// API Key authentication
export const ApiKeyAuthSchema = BaseAuthSchema.extend({
  type: z.literal('api_key'),
  key: z.string(),
  value: z.string(),
  in: z.enum(['header', 'query']),
  name: z.string(), // Header name or query parameter name
});

// OAuth2 authentication
export const OAuth2AuthSchema = BaseAuthSchema.extend({
  type: z.literal('oauth2'),
  token: z.string().optional(),
  token_type: z.enum(['bearer']).optional().default('bearer'),
  // OAuth2 configuration fields
  client_id: z.string(),
  authorization_url: z.string().url(),
  token_url: z.string().url(),
  redirect_uri: z.string().url(),
  flow: OAuth2FlowSchema,
  client_secret: z.string().optional(),
  scope: z.string().optional(),
});

// Custom authentication (custom headers)
export const CustomAuthSchema = BaseAuthSchema.extend({
  type: z.literal('custom'),
  headers: z.record(z.string(), z.string()),
});

// Union of all authentication types
export const AuthSchema = z.discriminatedUnion('type', [
  BasicAuthSchema,
  BearerAuthSchema,
  ApiKeyAuthSchema,
  OAuth2AuthSchema,
  CustomAuthSchema,
]);

// Type definitions
export type Auth = z.infer<typeof AuthSchema>;
export type BasicAuth = z.infer<typeof BasicAuthSchema>;
export type BearerAuth = z.infer<typeof BearerAuthSchema>;
export type ApiKeyAuth = z.infer<typeof ApiKeyAuthSchema>;
export type OAuth2Auth = z.infer<typeof OAuth2AuthSchema>;
export type CustomAuth = z.infer<typeof CustomAuthSchema>;

// OAuth2 configuration
export const OAuth2ConfigSchema = z.object({
  client_id: z.string(),
  client_secret: z.string().optional(),
  authorization_url: z.string().url(),
  token_url: z.string().url(),
  redirect_uri: z.string().url(),
  scope: z.string().optional(),
  flow: OAuth2FlowSchema,
});

// OAuth2 token response
export const OAuth2TokenResponseSchema = z.object({
  access_token: z.string(),
  token_type: z.string().optional().default('bearer'),
  expires_in: z.number().optional(),
  refresh_token: z.string().optional(),
  scope: z.string().optional(),
});

// Session management
export const SessionSchema = z.object({
  id: z.string(),
  created: z.string(),
  expires: z.string(),
  auth: AuthSchema,
});

export type OAuth2Flow = z.infer<typeof OAuth2FlowSchema>;
export type OAuth2Config = z.infer<typeof OAuth2ConfigSchema>;
export type OAuth2TokenResponse = z.infer<typeof OAuth2TokenResponseSchema>;
export type Session = z.infer<typeof SessionSchema>;

// Session storage
const sessions = new Map<string, Session>();

/**
 * Apply authentication to request headers and url
 */
export function applyAuthentication(
  auth: Auth | undefined,
  headers: Record<string, string>,
  url: URL
): { headers: Record<string, string>; url: URL } {
  if (!auth) {
    return { headers, url };
  }

  // Clone headers and URL to avoid mutating the originals
  const newHeaders = { ...headers };
  const newUrl = new URL(url.toString());

  try {
    switch (auth.type) {
      case 'basic': {
        const { username, password } = auth;
        const credentials = Buffer.from(`${username}:${password}`).toString('base64');
        newHeaders['Authorization'] = `Basic ${credentials}`;
        break;
      }
      case 'bearer': {
        const { token } = auth;
        newHeaders['Authorization'] = `Bearer ${token}`;
        break;
      }
      case 'api_key': {
        const { key, value, in: location, name } = auth;
        if (location === 'header') {
          newHeaders[name] = value;
        } else if (location === 'query') {
          newUrl.searchParams.set(name, value);
        }
        break;
      }
      case 'oauth2': {
        const { token, token_type } = auth;
        newHeaders['Authorization'] = `${token_type.charAt(0).toUpperCase() + token_type.slice(1)} ${token}`;
        break;
      }
      case 'custom': {
        const { headers: customHeaders } = auth;
        Object.entries(customHeaders).forEach(([key, value]) => {
          newHeaders[key] = value;
        });
        break;
      }
      default: {
        throw new AuthenticationError(`Unsupported authentication type: ${(auth as any).type}`);
      }
    }

    return { headers: newHeaders, url: newUrl };
  } catch (error) {
    if (error instanceof AuthenticationError) {
      throw error;
    }
    logger.error('Error applying authentication', error);
    throw new AuthenticationError('Failed to apply authentication');
  }
}

/**
 * Validate authentication configuration
 */
export function validateAuthentication(auth: unknown): Auth {
  try {
    return AuthSchema.parse(auth);
  } catch (error) {
    logger.error('Invalid authentication configuration', error);
    throw new AuthenticationError('Invalid authentication configuration');
  }
}

/**
 * Create a new OAuth2 authorization URL
 */
export function createOAuth2AuthUrl(config: OAuth2Config): string {
  const params = new URLSearchParams({
    client_id: config.client_id,
    redirect_uri: config.redirect_uri,
    response_type: config.flow === 'implicit' ? 'token' : 'code',
    ...(config.scope && { scope: config.scope }),
    state: crypto.randomBytes(16).toString('hex'),
  });

  return `${config.authorization_url}?${params.toString()}`;
}

/**
 * Exchange OAuth2 authorization code for tokens
 */
export async function exchangeOAuth2Code(
  config: OAuth2Config,
  code: string
): Promise<OAuth2TokenResponse> {
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: config.client_id,
    redirect_uri: config.redirect_uri,
    ...(config.client_secret && { client_secret: config.client_secret }),
  });

  const response = await fetch(config.token_url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  if (!response.ok) {
    throw new AuthenticationError('Failed to exchange OAuth2 code for tokens');
  }

  const data = await response.json();
  return OAuth2TokenResponseSchema.parse(data);
}

/**
 * Create a new session
 */
export function createSession(auth: Auth, expiresIn: number = 3600): Session {
  const now = new Date();
  const session: Session = {
    id: crypto.randomBytes(16).toString('hex'),
    created: now.toISOString(),
    expires: new Date(now.getTime() + expiresIn * 1000).toISOString(),
    auth,
  };

  sessions.set(session.id, session);
  return session;
}

/**
 * Get a session by ID
 */
export function getSession(id: string): Session | undefined {
  const session = sessions.get(id);
  if (!session) return undefined;

  // Check if session is expired
  if (new Date(session.expires) < new Date()) {
    sessions.delete(id);
    return undefined;
  }

  return session;
}

/**
 * Delete a session
 */
export function deleteSession(id: string): void {
  sessions.delete(id);
}