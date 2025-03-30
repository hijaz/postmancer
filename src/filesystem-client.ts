/**
 * Filesystem client for the Postmancer MCP server
 * This module handles interactions with the filesystem
 * for storage operations.
 */

import fs from 'fs/promises';
import path from 'path';
import logger from './logger.js';
import { getStoragePath, getCollectionsPath, getEnvironmentsPath } from './storage.js';

/**
 * Check if a directory exists, create it if it doesn't
 */
export async function ensureDirectoryExists(dirPath: string): Promise<void> {
  try {
    await fs.mkdir(dirPath, { recursive: true });
    logger.debug(`Ensured directory exists: ${dirPath}`);
  } catch (error) {
    logger.error(`Failed to create directory: ${dirPath}`, error);
    throw error;
  }
}

/**
 * Initialize the storage directory structure
 */
export async function initializeStorage(): Promise<void> {
  const storagePath = getStoragePath();
  const collectionsPath = getCollectionsPath();
  const environmentsPath = getEnvironmentsPath();

  logger.info(`Initializing storage in ${storagePath}`);
  
  try {
    // Create main storage directory
    await ensureDirectoryExists(storagePath);
    
    // Create collections directory
    await ensureDirectoryExists(collectionsPath);
    
    // Create environments directory
    await ensureDirectoryExists(environmentsPath);
    
    logger.info('Storage initialization completed successfully');
  } catch (error) {
    logger.error('Storage initialization failed', error);
    throw error;
  }
}

/**
 * Check if a file exists
 */
export async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Read a JSON file from disk
 */
export async function readJsonFile<T>(filePath: string): Promise<T> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(content) as T;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(`File not found: ${filePath}`);
    }
    logger.error(`Failed to read file: ${filePath}`, error);
    throw error;
  }
}

/**
 * Write a JSON file to disk
 */
export async function writeJsonFile<T>(filePath: string, data: T): Promise<void> {
  try {
    // Ensure parent directory exists
    const dir = path.dirname(filePath);
    await ensureDirectoryExists(dir);
    
    // Write file with pretty formatting for readability
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
    logger.debug(`Successfully wrote file: ${filePath}`);
  } catch (error) {
    logger.error(`Failed to write file: ${filePath}`, error);
    throw error;
  }
}

/**
 * List files in a directory
 */
export async function listFiles(dirPath: string): Promise<string[]> {
  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    return entries
      .filter(entry => entry.isFile())
      .map(entry => entry.name);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      // Return empty array if directory doesn't exist
      return [];
    }
    logger.error(`Failed to list files in directory: ${dirPath}`, error);
    throw error;
  }
}

/**
 * Delete a file
 */
export async function deleteFile(filePath: string): Promise<void> {
  try {
    await fs.unlink(filePath);
    logger.debug(`Successfully deleted file: ${filePath}`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      // File doesn't exist, which is fine for deletion
      return;
    }
    logger.error(`Failed to delete file: ${filePath}`, error);
    throw error;
  }
}