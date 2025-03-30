/**
 * Storage implementation for the Postmancer MCP server
 * This module handles persistence of collections, requests, and environment variables
 * using the filesystem MCP server for actual file operations.
 */

import path from 'path';
import os from 'os';
import { z } from 'zod';
import crypto from 'crypto';
import logger from './logger.js';
import { CollectionRequestSchema, EnhancedHttpRequestSchema, EnvironmentVariableSchema } from './schemas.js';
import { CollectionError, EnvironmentError } from './errors.js';

// Default base directory for storing collections and environments
// This can be overridden with the COLLECTIONS_PATH environment variable
export const DEFAULT_STORAGE_PATH = path.join(os.homedir(), '.postmancer');

// Get storage path from environment or use default
export const getStoragePath = (): string => {
  return process.env.COLLECTIONS_PATH || DEFAULT_STORAGE_PATH;
};

// Directory structure
export const COLLECTIONS_DIR = 'collections';
export const ENVIRONMENTS_DIR = 'environments';

// Get absolute path for collections
export const getCollectionsPath = (): string => {
  return path.join(getStoragePath(), COLLECTIONS_DIR);
};

// Get absolute path for environments
export const getEnvironmentsPath = (): string => {
  return path.join(getStoragePath(), ENVIRONMENTS_DIR);
};

// Get collection file path
export const getCollectionFilePath = (collectionName: string): string => {
  // Sanitize collection name to prevent directory traversal
  const sanitizedName = sanitizeStorageName(collectionName);
  return path.join(getCollectionsPath(), `${sanitizedName}.json`);
};

// Get environment file path
export const getEnvironmentFilePath = (environmentName: string): string => {
  // Sanitize environment name to prevent directory traversal
  const sanitizedName = sanitizeStorageName(environmentName);
  return path.join(getEnvironmentsPath(), `${sanitizedName}.json`);
};

/**
 * Sanitize storage names to prevent directory traversal
 */
export function sanitizeStorageName(name: string): string {
  // Replace any non-alphanumeric characters with underscores
  // This prevents path traversal and invalid file names
  return name.replace(/[^a-z0-9_-]/gi, '_');
}

/**
 * Collection metadata schema
 */
export const CollectionMetadataSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  created: z.string(),  // ISO date string
  modified: z.string(), // ISO date string
});

export type CollectionMetadata = z.infer<typeof CollectionMetadataSchema>;

/**
 * Collection schema for storage
 */
export const StoredCollectionSchema = z.object({
  metadata: CollectionMetadataSchema,
  requests: z.record(z.object({
    name: z.string(),
    description: z.string().optional(),
    created: z.string(),  // ISO date string
    modified: z.string(), // ISO date string
    request: EnhancedHttpRequestSchema,
  })),
});

export type StoredCollection = z.infer<typeof StoredCollectionSchema>;

/**
 * Environment variable with optional encryption for secrets
 */
export const StoredEnvironmentVariableSchema = z.object({
  name: z.string(),
  value: z.string(),
  is_secret: z.boolean().default(false),
  encrypted: z.boolean().default(false),
});

export type StoredEnvironmentVariable = z.infer<typeof StoredEnvironmentVariableSchema>;

/**
 * Environment schema for storage
 */
export const StoredEnvironmentSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  created: z.string(),  // ISO date string
  modified: z.string(), // ISO date string
  variables: z.array(StoredEnvironmentVariableSchema),
});

export type StoredEnvironment = z.infer<typeof StoredEnvironmentSchema>;

/**
 * Create a new collection
 */
export async function createCollection(
  name: string, 
  description?: string
): Promise<StoredCollection> {
  const now = new Date().toISOString();
  
  const collection: StoredCollection = {
    metadata: {
      name,
      description,
      created: now,
      modified: now,
    },
    requests: {},
  };
  
  return collection;
}

/**
 * Create a new environment
 */
export async function createEnvironment(
  name: string,
  description?: string
): Promise<StoredEnvironment> {
  const now = new Date().toISOString();
  
  const environment: StoredEnvironment = {
    name,
    description,
    created: now,
    modified: now,
    variables: [],
  };
  
  return environment;
}

/**
 * Encrypt sensitive environment variables
 * Uses a basic encryption strategy - in a production environment,
 * you'd want a more robust key management solution
 */
export function encryptValue(value: string): string {
  // In real implementation, we'd use a proper key management system
  // and securely store/retrieve encryption keys
  // This is a simplified version for demonstration
  const encryptionKey = process.env.ENCRYPTION_KEY || 'DefaultEncryptionKey123!';
  
  try {
    // Generate a random 16-byte IV
    const iv = crypto.randomBytes(16);
    
    // Create cipher using AES-256-CBC
    const cipher = crypto.createCipheriv(
      'aes-256-cbc',
      // Derive a 32-byte key from the encryption key
      crypto.createHash('sha256').update(encryptionKey).digest().slice(0, 32),
      iv
    );
    
    // Encrypt the value
    let encrypted = cipher.update(value, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    // Return IV + encrypted value, both base64 encoded
    return `${iv.toString('base64')}:${encrypted}`;
  } catch (error) {
    logger.error('Error encrypting value', error);
    throw new EnvironmentError('Failed to encrypt value');
  }
}

/**
 * Decrypt sensitive environment variables
 */
export function decryptValue(encryptedValue: string): string {
  const encryptionKey = process.env.ENCRYPTION_KEY || 'DefaultEncryptionKey123!';
  
  try {
    // Split IV and encrypted data
    const [ivBase64, encryptedData] = encryptedValue.split(':');
    if (!ivBase64 || !encryptedData) {
      throw new Error('Invalid encrypted value format');
    }
    
    // Decode IV
    const iv = Buffer.from(ivBase64, 'base64');
    
    // Create decipher
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      // Derive key same as in encryption
      crypto.createHash('sha256').update(encryptionKey).digest().slice(0, 32),
      iv
    );
    
    // Decrypt
    let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    logger.error('Error decrypting value', error);
    throw new EnvironmentError('Failed to decrypt value');
  }
}

/**
 * Perform variable substitution in request properties
 * Replaces {{variable_name}} with the corresponding environment variable value
 */
export function substituteVariables(
  request: z.infer<typeof EnhancedHttpRequestSchema>,
  variables: Record<string, string>
): z.infer<typeof EnhancedHttpRequestSchema> {
  const substituteInString = (str: string): string => {
    return str.replace(/\{\{([^}]+)\}\}/g, (_, variableName) => {
      const trimmedName = variableName.trim();
      return variables[trimmedName] !== undefined 
        ? variables[trimmedName] 
        : `{{${trimmedName}}}`;  // Keep original if not found
    });
  };
  
  const result = { ...request };
  
  // Substitute URL
  if (result.url) {
    result.url = substituteInString(result.url);
  }
  
  // Substitute headers
  if (result.headers) {
    const newHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(result.headers)) {
      newHeaders[key] = substituteInString(value);
    }
    result.headers = newHeaders;
  }
  
  // Substitute body
  if (result.body) {
    result.body = substituteInString(result.body);
  }
  
  // Substitute query parameters
  if (result.query_params) {
    const newParams: Record<string, string> = {};
    for (const [key, value] of Object.entries(result.query_params)) {
      newParams[key] = substituteInString(value);
    }
    result.query_params = newParams;
  }
  
  return result;
}