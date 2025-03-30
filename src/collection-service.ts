/**
 * Collection service for the Postmancer MCP server
 * Provides operations for managing collections and requests
 */

import path from 'path';
import { z } from 'zod';
import logger from './logger.js';
import { CollectionError } from './errors.js';
import { CollectionRequestSchema, EnhancedHttpRequestSchema } from './schemas.js';
import { 
  StoredCollection, 
  StoredCollectionSchema,
  createCollection,
  getCollectionFilePath,
  sanitizeStorageName,
  getCollectionsPath
} from './storage.js';
import {
  fileExists,
  readJsonFile,
  writeJsonFile,
  listFiles
} from './filesystem-client.js';

/**
 * Create a new collection
 */
export async function createNewCollection(name: string, description?: string): Promise<StoredCollection> {
  const sanitizedName = sanitizeStorageName(name);
  const filePath = getCollectionFilePath(sanitizedName);
  
  // Check if collection already exists
  if (await fileExists(filePath)) {
    throw new CollectionError(`Collection '${name}' already exists`);
  }
  
  // Create new collection object
  const collection = await createCollection(name, description);
  
  // Save to disk
  await writeJsonFile(filePath, collection);
  
  logger.info(`Created new collection: ${name}`);
  return collection;
}

/**
 * Get a collection by name
 */
export async function getCollection(name: string): Promise<StoredCollection> {
  const sanitizedName = sanitizeStorageName(name);
  const filePath = getCollectionFilePath(sanitizedName);
  
  try {
    const collection = await readJsonFile<StoredCollection>(filePath);
    
    // Validate collection data
    return StoredCollectionSchema.parse(collection);
  } catch (error) {
    if (error instanceof Error && error.message.includes('File not found')) {
      throw new CollectionError(`Collection '${name}' not found`);
    }
    logger.error(`Error loading collection: ${name}`, error);
    throw new CollectionError(`Failed to load collection '${name}'`);
  }
}

/**
 * List all collections
 */
export async function listCollections(): Promise<Array<{ name: string, description?: string }>> {
  try {
    const collectionsDir = getCollectionsPath();
    const files = await listFiles(collectionsDir);
    
    // Get only JSON files and remove extension
    const collectionFiles = files.filter(file => file.endsWith('.json'));
    
    // Load metadata for each collection
    const collections = await Promise.all(
      collectionFiles.map(async file => {
        const filePath = path.join(collectionsDir, file);
        try {
          const collection = await readJsonFile<StoredCollection>(filePath);
          return {
            name: collection.metadata.name,
            description: collection.metadata.description
          };
        } catch (error) {
          logger.warn(`Skipping invalid collection file: ${file}`, error);
          return null;
        }
      })
    );
    
    // Filter out failed loads
    return collections.filter(Boolean) as Array<{ name: string, description?: string }>;
  } catch (error) {
    logger.error('Failed to list collections', error);
    throw new CollectionError('Failed to list collections');
  }
}

/**
 * Delete a collection
 */
export async function deleteCollection(name: string): Promise<void> {
  const sanitizedName = sanitizeStorageName(name);
  const filePath = getCollectionFilePath(sanitizedName);
  
  try {
    // Verify collection exists before deleting
    if (!await fileExists(filePath)) {
      throw new CollectionError(`Collection '${name}' not found`);
    }
    
    // Delete the file
    await deleteFile(filePath);
    logger.info(`Deleted collection: ${name}`);
  } catch (error) {
    if (error instanceof CollectionError) {
      throw error;
    }
    logger.error(`Failed to delete collection: ${name}`, error);
    throw new CollectionError(`Failed to delete collection '${name}'`);
  }
}

/**
 * Save a request to a collection
 */
export async function saveRequest(
  collectionName: string,
  requestName: string,
  request: z.infer<typeof EnhancedHttpRequestSchema>,
  description?: string
): Promise<void> {
  try {
    // Get the collection
    const collection = await getCollection(collectionName);
    
    // Create or update the request
    const now = new Date().toISOString();
    const existingRequest = collection.requests[requestName];
    
    collection.requests[requestName] = {
      name: requestName,
      description: description || existingRequest?.description,
      created: existingRequest?.created || now,
      modified: now,
      request
    };
    
    // Update modified timestamp on collection
    collection.metadata.modified = now;
    
    // Save the updated collection
    const filePath = getCollectionFilePath(sanitizeStorageName(collectionName));
    await writeJsonFile(filePath, collection);
    
    logger.info(`Saved request '${requestName}' to collection '${collectionName}'`);
  } catch (error) {
    if (error instanceof CollectionError) {
      throw error;
    }
    logger.error(`Failed to save request '${requestName}' to collection '${collectionName}'`, error);
    throw new CollectionError(`Failed to save request '${requestName}' to collection '${collectionName}'`);
  }
}

/**
 * Get a request from a collection
 */
export async function getRequest(
  collectionName: string,
  requestName: string
): Promise<z.infer<typeof EnhancedHttpRequestSchema>> {
  try {
    // Get the collection
    const collection = await getCollection(collectionName);
    
    // Check if request exists
    if (!collection.requests[requestName]) {
      throw new CollectionError(`Request '${requestName}' not found in collection '${collectionName}'`);
    }
    
    return collection.requests[requestName].request;
  } catch (error) {
    if (error instanceof CollectionError) {
      throw error;
    }
    logger.error(`Failed to get request '${requestName}' from collection '${collectionName}'`, error);
    throw new CollectionError(`Failed to get request '${requestName}' from collection '${collectionName}'`);
  }
}

/**
 * List all requests in a collection
 */
export async function listRequests(
  collectionName: string
): Promise<Array<{ name: string, description?: string }>> {
  try {
    // Get the collection
    const collection = await getCollection(collectionName);
    
    // Map requests to name and description
    return Object.values(collection.requests).map(request => ({
      name: request.name,
      description: request.description
    }));
  } catch (error) {
    if (error instanceof CollectionError) {
      throw error;
    }
    logger.error(`Failed to list requests for collection '${collectionName}'`, error);
    throw new CollectionError(`Failed to list requests for collection '${collectionName}'`);
  }
}

/**
 * Delete a request from a collection
 */
export async function deleteRequest(
  collectionName: string,
  requestName: string
): Promise<void> {
  try {
    // Get the collection
    const collection = await getCollection(collectionName);
    
    // Check if request exists
    if (!collection.requests[requestName]) {
      throw new CollectionError(`Request '${requestName}' not found in collection '${collectionName}'`);
    }
    
    // Remove the request
    delete collection.requests[requestName];
    
    // Update modified timestamp
    collection.metadata.modified = new Date().toISOString();
    
    // Save the updated collection
    const filePath = getCollectionFilePath(sanitizeStorageName(collectionName));
    await writeJsonFile(filePath, collection);
    
    logger.info(`Deleted request '${requestName}' from collection '${collectionName}'`);
  } catch (error) {
    if (error instanceof CollectionError) {
      throw error;
    }
    logger.error(`Failed to delete request '${requestName}' from collection '${collectionName}'`, error);
    throw new CollectionError(`Failed to delete request '${requestName}' from collection '${collectionName}'`);
  }
}

/**
 * Import a Postman/Insomnia collection (basic implementation)
 * This is a simplified version and would need to be expanded
 * to handle all the features of Postman/Insomnia formats
 */
export async function importCollection(
  name: string,
  importData: any,
  format: 'postman' | 'insomnia' = 'postman'
): Promise<StoredCollection> {
  try {
    // Create a new collection
    const collection = await createNewCollection(name);
    
    // Add request items based on format
    if (format === 'postman' && importData.item && Array.isArray(importData.item)) {
      for (const item of importData.item) {
        if (item.request) {
          // Convert Postman request to our format
          const request: z.infer<typeof EnhancedHttpRequestSchema> = {
            url: item.request.url?.raw || '',
            method: item.request.method || 'GET',
            // Convert headers array to record
            headers: item.request.header?.reduce((acc: Record<string, string>, h: any) => {
              if (h.key && h.value) {
                acc[h.key] = h.value;
              }
              return acc;
            }, {}),
            // Convert body
            body: item.request.body?.raw,
          };
          
          // Save the request
          await saveRequest(name, item.name, request, item.description);
        }
      }
    } else if (format === 'insomnia' && importData.resources && Array.isArray(importData.resources)) {
      // Simplified Insomnia format handling
      const requests = importData.resources.filter((r: any) => r._type === 'request');
      
      for (const item of requests) {
        const request: z.infer<typeof EnhancedHttpRequestSchema> = {
          url: item.url || '',
          method: item.method || 'GET',
          headers: item.headers?.reduce((acc: Record<string, string>, h: any) => {
            if (h.name && h.value) {
              acc[h.name] = h.value;
            }
            return acc;
          }, {}),
          body: item.body?.text,
        };
        
        // Save the request
        await saveRequest(name, item.name, request, item.description);
      }
    }
    
    return collection;
  } catch (error) {
    logger.error(`Failed to import collection: ${name}`, error);
    throw new CollectionError(`Failed to import collection: ${error instanceof Error ? error.message : String(error)}`);
  }
}

// Function missing from filesytem-client - add this to maintain integrity
import { deleteFile } from './filesystem-client.js';