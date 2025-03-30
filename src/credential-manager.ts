/**
 * Credential manager for the Postmancer MCP server
 * Provides secure storage and retrieval of authentication credentials
 */

import { z } from 'zod';
import path from 'path';
import crypto from 'crypto';
import logger from './logger.js';
import { AuthenticationError } from './errors.js';
import { 
  Auth, 
  AuthSchema,
  OAuth2Config,
  OAuth2TokenResponse,
  OAuth2TokenResponseSchema,
  Session
} from './authentication.js';
import { fileExists, readJsonFile, writeJsonFile } from './filesystem-client.js';
import { getStoragePath } from './storage.js';

// Define encryption key from environment or generate one
const ENCRYPTION_KEY = process.env.POSTMANCER_ENCRYPTION_KEY || 
                       crypto.randomBytes(32).toString('hex');

// Define initialization vector (IV) length
const IV_LENGTH = 16;

// Define credential storage location
const CREDENTIALS_DIR = path.join(getStoragePath(), 'credentials');

/**
 * Stored credential schema with metadata
 */
export const StoredCredentialSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.string(),
  created: z.string(),
  modified: z.string(),
  data: z.any(), // Encrypted data
  iv: z.string(), // Initialization vector for decryption
});

export type StoredCredential = z.infer<typeof StoredCredentialSchema>;

// OAuth2 token storage schema
const OAuth2TokenSchema = z.object({
  access_token: z.string(),
  refresh_token: z.string().optional(),
  expires_at: z.string(),
  token_type: z.string().optional().default('bearer'),
  scope: z.string().optional(),
});

type OAuth2Token = z.infer<typeof OAuth2TokenSchema>;

// Token storage
const tokens = new Map<string, OAuth2Token>();

/**
 * Initialize the credentials directory
 */
export async function initializeCredentialStorage(): Promise<void> {
  try {
    await ensureCredentialsDirectory();
    logger.info('Credential storage initialized');
  } catch (error) {
    logger.error('Failed to initialize credential storage', error);
    throw error;
  }
}

/**
 * Ensure the credentials directory exists
 */
async function ensureCredentialsDirectory(): Promise<void> {
  const fs = await import('fs/promises');
  try {
    await fs.mkdir(CREDENTIALS_DIR, { recursive: true });
  } catch (error) {
    logger.error('Failed to create credentials directory', error);
    throw error;
  }
}

/**
 * Get the file path for a credential
 */
function getCredentialPath(id: string): string {
  // Sanitize ID to prevent path traversal
  const sanitizedId = id.replace(/[^a-zA-Z0-9_-]/g, '_');
  return path.join(CREDENTIALS_DIR, `${sanitizedId}.json`);
}

/**
 * Encrypt authentication data
 */
function encryptData(data: Auth): { encryptedData: string; iv: string } {
  try {
    // Generate a random initialization vector
    const iv = crypto.randomBytes(IV_LENGTH);
    
    // Create cipher with key and iv
    const key = Buffer.from(ENCRYPTION_KEY, 'hex');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    // Encrypt the data
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return {
      encryptedData: encrypted,
      iv: iv.toString('hex')
    };
  } catch (error) {
    logger.error('Failed to encrypt credential data', error);
    throw new AuthenticationError('Failed to encrypt credential data');
  }
}

/**
 * Decrypt authentication data
 */
function decryptData(encryptedData: string, iv: string): Auth {
  try {
    // Create decipher with key and iv
    const key = Buffer.from(ENCRYPTION_KEY, 'hex');
    const ivBuffer = Buffer.from(iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, ivBuffer);
    
    // Decrypt the data
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    // Parse and validate the decrypted data
    return AuthSchema.parse(JSON.parse(decrypted));
  } catch (error) {
    logger.error('Failed to decrypt credential data', error);
    throw new AuthenticationError('Failed to decrypt credential data');
  }
}

/**
 * Save an authentication credential
 */
export async function saveCredential(
  id: string,
  name: string,
  auth: Auth
): Promise<StoredCredential> {
  try {
    await ensureCredentialsDirectory();
    
    // Check if credential already exists
    const credentialPath = getCredentialPath(id);
    let existingCredential: StoredCredential | null = null;
    
    if (await fileExists(credentialPath)) {
      existingCredential = await readJsonFile<StoredCredential>(credentialPath);
    }
    
    // Encrypt the authentication data
    const { encryptedData, iv } = encryptData(auth);
    
    // Create or update the credential
    const now = new Date().toISOString();
    const credential: StoredCredential = {
      id,
      name,
      type: auth.type,
      created: existingCredential?.created || now,
      modified: now,
      data: encryptedData,
      iv
    };
    
    // Save to disk
    await writeJsonFile(credentialPath, credential);
    
    logger.info(`Saved credential: ${id}`);
    return credential;
  } catch (error) {
    if (error instanceof AuthenticationError) {
      throw error;
    }
    logger.error(`Failed to save credential: ${id}`, error);
    throw new AuthenticationError(`Failed to save credential: ${id}`);
  }
}

/**
 * Get an authentication credential
 */
export async function getCredential(id: string): Promise<Auth> {
  try {
    const credentialPath = getCredentialPath(id);
    
    // Check if credential exists
    if (!await fileExists(credentialPath)) {
      throw new AuthenticationError(`Credential not found: ${id}`);
    }
    
    // Read the credential
    const credential = await readJsonFile<StoredCredential>(credentialPath);
    
    // Decrypt the data
    return decryptData(credential.data, credential.iv);
  } catch (error) {
    if (error instanceof AuthenticationError) {
      throw error;
    }
    logger.error(`Failed to get credential: ${id}`, error);
    throw new AuthenticationError(`Failed to get credential: ${id}`);
  }
}

/**
 * Delete an authentication credential
 */
export async function deleteCredential(id: string): Promise<void> {
  try {
    const credentialPath = getCredentialPath(id);
    
    // Check if credential exists
    if (!await fileExists(credentialPath)) {
      throw new AuthenticationError(`Credential not found: ${id}`);
    }
    
    // Delete the file
    const fs = await import('fs/promises');
    await fs.unlink(credentialPath);
    
    logger.info(`Deleted credential: ${id}`);
  } catch (error) {
    if (error instanceof AuthenticationError) {
      throw error;
    }
    logger.error(`Failed to delete credential: ${id}`, error);
    throw new AuthenticationError(`Failed to delete credential: ${id}`);
  }
}

/**
 * List all saved credentials (without sensitive data)
 */
export async function listCredentials(): Promise<Array<{ id: string; name: string; type: string }>> {
  try {
    await ensureCredentialsDirectory();
    
    // Get all credential files
    const fs = await import('fs/promises');
    const files = await fs.readdir(CREDENTIALS_DIR);
    
    // Read and parse credential files
    const credentials = await Promise.all(
      files
        .filter(file => file.endsWith('.json'))
        .map(async (file) => {
          try {
            const filePath = path.join(CREDENTIALS_DIR, file);
            const credential = await readJsonFile<StoredCredential>(filePath);
            return {
              id: credential.id,
              name: credential.name,
              type: credential.type
            };
          } catch (error) {
            logger.warn(`Failed to read credential file: ${file}`, error);
            return null;
          }
        })
    );
    
    // Filter out null values
    return credentials.filter(Boolean) as Array<{ id: string; name: string; type: string }>;
  } catch (error) {
    logger.error('Failed to list credentials', error);
    throw new AuthenticationError('Failed to list credentials');
  }
}

/**
 * Save OAuth2 tokens
 */
export async function saveOAuth2Tokens(
  credentialId: string,
  tokenResponse: OAuth2TokenResponse
): Promise<void> {
  const token: OAuth2Token = {
    access_token: tokenResponse.access_token,
    refresh_token: tokenResponse.refresh_token,
    expires_at: new Date(Date.now() + (tokenResponse.expires_in || 3600) * 1000).toISOString(),
    token_type: tokenResponse.token_type,
    scope: tokenResponse.scope,
  };

  tokens.set(credentialId, token);
  logger.info(`Saved OAuth2 tokens for credential: ${credentialId}`);
}

/**
 * Get OAuth2 tokens
 */
export function getOAuth2Tokens(credentialId: string): OAuth2Token | undefined {
  const token = tokens.get(credentialId);
  if (!token) return undefined;

  // Check if token is expired
  if (new Date(token.expires_at) < new Date()) {
    tokens.delete(credentialId);
    return undefined;
  }

  return token;
}

/**
 * Refresh OAuth2 tokens
 */
export async function refreshOAuth2Tokens(
  credentialId: string,
  config: OAuth2Config
): Promise<void> {
  const token = tokens.get(credentialId);
  if (!token?.refresh_token) {
    throw new AuthenticationError('No refresh token available');
  }

  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: token.refresh_token,
    client_id: config.client_id,
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
    throw new AuthenticationError('Failed to refresh OAuth2 tokens');
  }

  const data = await response.json();
  const tokenResponse = OAuth2TokenResponseSchema.parse(data);
  await saveOAuth2Tokens(credentialId, tokenResponse);
}

/**
 * Save session to persistent storage
 */
export async function saveSession(session: Session): Promise<void> {
  try {
    const sessionPath = path.join(CREDENTIALS_DIR, 'sessions', `${session.id}.json`);
    await writeJsonFile(sessionPath, session);
    logger.info(`Saved session: ${session.id}`);
  } catch (error) {
    logger.error(`Failed to save session: ${session.id}`, error);
    throw new AuthenticationError(`Failed to save session: ${session.id}`);
  }
}

/**
 * Load session from persistent storage
 */
export async function loadSession(id: string): Promise<Session | undefined> {
  try {
    const sessionPath = path.join(CREDENTIALS_DIR, 'sessions', `${id}.json`);
    if (!await fileExists(sessionPath)) {
      return undefined;
    }

    const session = await readJsonFile<Session>(sessionPath);
    
    // Check if session is expired
    if (new Date(session.expires) < new Date()) {
      await deleteSession(id);
      return undefined;
    }

    return session;
  } catch (error) {
    logger.error(`Failed to load session: ${id}`, error);
    return undefined;
  }
}

/**
 * Delete session from persistent storage
 */
export async function deleteSession(id: string): Promise<void> {
  try {
    const sessionPath = path.join(CREDENTIALS_DIR, 'sessions', `${id}.json`);
    if (await fileExists(sessionPath)) {
      const fs = await import('fs/promises');
      await fs.unlink(sessionPath);
      logger.info(`Deleted session: ${id}`);
    }
  } catch (error) {
    logger.error(`Failed to delete session: ${id}`, error);
    throw new AuthenticationError(`Failed to delete session: ${id}`);
  }
}