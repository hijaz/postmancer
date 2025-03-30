/**
 * Authentication helper tools for the Postmancer MCP server
 * Provides tools for managing OAuth2 tokens and sessions
 */

import { z } from 'zod';
import logger from './logger.js';
import { AuthenticationError } from './errors.js';
import { 
  OAuth2Config,
  OAuth2ConfigSchema,
  OAuth2Flow,
  createOAuth2AuthUrl,
  exchangeOAuth2Code,
  createSession,
  getSession,
  deleteSession
} from './authentication.js';
import {
  saveOAuth2Tokens,
  getOAuth2Tokens,
  refreshOAuth2Tokens,
  saveSession as persistSession,
  loadSession as loadPersistentSession,
  deleteSession as deletePersistentSession,
  getCredential
} from './credential-manager.js';

// Tool schemas
export const OAuth2InitSchema = z.object({
  config: OAuth2ConfigSchema,
  credential_id: z.string(),
});

export const OAuth2CallbackSchema = z.object({
  credential_id: z.string(),
  code: z.string(),
  state: z.string(),
});

export const SessionCreateSchema = z.object({
  auth: z.any(), // Using any since we don't want to duplicate the AuthSchema
  expires_in: z.number().optional(),
});

export const SessionGetSchema = z.object({
  session_id: z.string(),
});

export const SessionDeleteSchema = z.object({
  session_id: z.string(),
});

/**
 * Initialize OAuth2 flow
 */
export async function initOAuth2Flow(args: z.infer<typeof OAuth2InitSchema>): Promise<string> {
  try {
    const { config, credential_id } = args;
    const authUrl = createOAuth2AuthUrl(config);
    logger.info(`Created OAuth2 authorization URL for credential: ${credential_id}`);
    return authUrl;
  } catch (error) {
    logger.error('Failed to initialize OAuth2 flow', error);
    throw new AuthenticationError('Failed to initialize OAuth2 flow');
  }
}

/**
 * Handle OAuth2 callback
 */
export async function handleOAuth2Callback(args: z.infer<typeof OAuth2CallbackSchema>): Promise<void> {
  try {
    const { credential_id, code } = args;
    
    // Get the OAuth2 config from the credential
    const credential = await getCredential(credential_id);
    if (!credential || credential.type !== 'oauth2') {
      throw new AuthenticationError('Invalid OAuth2 credential');
    }

    // Extract OAuth2 config from credential
    const config: OAuth2Config = {
      client_id: credential.client_id,
      authorization_url: credential.authorization_url,
      token_url: credential.token_url,
      redirect_uri: credential.redirect_uri,
      flow: credential.flow,
      client_secret: credential.client_secret,
      scope: credential.scope
    };

    const tokenResponse = await exchangeOAuth2Code(config, code);
    await saveOAuth2Tokens(credential_id, tokenResponse);
    
    logger.info(`Completed OAuth2 flow for credential: ${credential_id}`);
  } catch (error) {
    logger.error('Failed to handle OAuth2 callback', error);
    throw new AuthenticationError('Failed to handle OAuth2 callback');
  }
}

/**
 * Create a new session
 */
export async function createNewSession(args: z.infer<typeof SessionCreateSchema>): Promise<{ id: string }> {
  try {
    const { auth, expires_in } = args;
    const session = createSession(auth, expires_in);
    await persistSession(session);
    logger.info(`Created new session: ${session.id}`);
    return { id: session.id };
  } catch (error) {
    logger.error('Failed to create session', error);
    throw new AuthenticationError('Failed to create session');
  }
}

/**
 * Get session details
 */
export async function getSessionDetails(args: z.infer<typeof SessionGetSchema>): Promise<any> {
  try {
    const { session_id } = args;
    
    // Try to get session from memory first
    let session = getSession(session_id);
    
    // If not in memory, try to load from persistent storage
    if (!session) {
      session = await loadPersistentSession(session_id);
    }
    
    if (!session) {
      throw new AuthenticationError('Session not found');
    }
    
    return session;
  } catch (error) {
    logger.error('Failed to get session details', error);
    throw new AuthenticationError('Failed to get session details');
  }
}

/**
 * Delete a session
 */
export async function deleteSessionById(args: z.infer<typeof SessionDeleteSchema>): Promise<void> {
  try {
    const { session_id } = args;
    
    // Delete from memory
    deleteSession(session_id);
    
    // Delete from persistent storage
    await deletePersistentSession(session_id);
    
    logger.info(`Deleted session: ${session_id}`);
  } catch (error) {
    logger.error('Failed to delete session', error);
    throw new AuthenticationError('Failed to delete session');
  }
}

/**
 * Refresh OAuth2 tokens
 */
export async function refreshTokens(credential_id: string): Promise<void> {
  try {
    const credential = await getCredential(credential_id);
    if (!credential || credential.type !== 'oauth2') {
      throw new AuthenticationError('Invalid OAuth2 credential');
    }

    // Extract OAuth2 config from credential
    const config: OAuth2Config = {
      client_id: credential.client_id,
      authorization_url: credential.authorization_url,
      token_url: credential.token_url,
      redirect_uri: credential.redirect_uri,
      flow: credential.flow,
      client_secret: credential.client_secret,
      scope: credential.scope
    };

    await refreshOAuth2Tokens(credential_id, config);
    logger.info(`Refreshed OAuth2 tokens for credential: ${credential_id}`);
  } catch (error) {
    logger.error('Failed to refresh tokens', error);
    throw new AuthenticationError('Failed to refresh tokens');
  }
}