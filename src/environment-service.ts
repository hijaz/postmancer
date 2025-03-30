/**
 * Environment service for the Postmancer MCP server
 * Provides operations for managing environment variables
 */

import { z } from 'zod';
import logger from './logger.js';
import { EnvironmentError } from './errors.js';
import { EnvironmentVariableSchema } from './schemas.js';
import { 
  StoredEnvironment, 
  StoredEnvironmentSchema,
  StoredEnvironmentVariableSchema,
  createEnvironment,
  getEnvironmentFilePath,
  sanitizeStorageName,
  getEnvironmentsPath,
  encryptValue,
  decryptValue
} from './storage.js';
import {
  fileExists,
  readJsonFile,
  writeJsonFile,
  listFiles
} from './filesystem-client.js';

/**
 * Default environment name
 */
export const DEFAULT_ENVIRONMENT = 'default';

/**
 * Create a new environment
 */
export async function createNewEnvironment(name: string, description?: string): Promise<StoredEnvironment> {
  const sanitizedName = sanitizeStorageName(name);
  const filePath = getEnvironmentFilePath(sanitizedName);
  
  // Check if environment already exists
  if (await fileExists(filePath)) {
    throw new EnvironmentError(`Environment '${name}' already exists`);
  }
  
  // Create new environment object
  const environment = await createEnvironment(name, description);
  
  // Save to disk
  await writeJsonFile(filePath, environment);
  
  logger.info(`Created new environment: ${name}`);
  return environment;
}

/**
 * Ensure the default environment exists
 */
export async function ensureDefaultEnvironment(): Promise<StoredEnvironment> {
  try {
    // Try to get the default environment
    return await getEnvironment(DEFAULT_ENVIRONMENT);
  } catch (error) {
    // Create default environment if it doesn't exist
    if (error instanceof EnvironmentError && error.message.includes('not found')) {
      return await createNewEnvironment(DEFAULT_ENVIRONMENT, 'Default environment for Postmancer');
    }
    throw error;
  }
}

/**
 * Get an environment by name
 */
export async function getEnvironment(name: string): Promise<StoredEnvironment> {
  const sanitizedName = sanitizeStorageName(name);
  const filePath = getEnvironmentFilePath(sanitizedName);
  
  try {
    const environment = await readJsonFile<StoredEnvironment>(filePath);
    
    // Validate environment data
    return StoredEnvironmentSchema.parse(environment);
  } catch (error) {
    if (error instanceof Error && error.message.includes('File not found')) {
      throw new EnvironmentError(`Environment '${name}' not found`);
    }
    logger.error(`Error loading environment: ${name}`, error);
    throw new EnvironmentError(`Failed to load environment '${name}'`);
  }
}

/**
 * List all environments
 */
export async function listEnvironments(): Promise<Array<{ name: string, description?: string }>> {
  try {
    const environmentsDir = getEnvironmentsPath();
    const files = await listFiles(environmentsDir);
    
    // Get only JSON files
    const environmentFiles = files.filter(file => file.endsWith('.json'));
    
    // Load metadata for each environment
    const environments = await Promise.all(
      environmentFiles.map(async file => {
        const filePath = `${environmentsDir}/${file}`;
        try {
          const environment = await readJsonFile<StoredEnvironment>(filePath);
          return {
            name: environment.name,
            description: environment.description
          };
        } catch (error) {
          logger.warn(`Skipping invalid environment file: ${file}`, error);
          return null;
        }
      })
    );
    
    // Filter out failed loads
    return environments.filter(Boolean) as Array<{ name: string, description?: string }>;
  } catch (error) {
    logger.error('Failed to list environments', error);
    throw new EnvironmentError('Failed to list environments');
  }
}

/**
 * Delete an environment
 */
export async function deleteEnvironment(name: string): Promise<void> {
  // Don't allow deleting default environment
  if (name === DEFAULT_ENVIRONMENT) {
    throw new EnvironmentError('Cannot delete the default environment');
  }
  
  const sanitizedName = sanitizeStorageName(name);
  const filePath = getEnvironmentFilePath(sanitizedName);
  
  try {
    // Verify environment exists before deleting
    if (!await fileExists(filePath)) {
      throw new EnvironmentError(`Environment '${name}' not found`);
    }
    
    // Delete the file
    await deleteFile(filePath);
    logger.info(`Deleted environment: ${name}`);
  } catch (error) {
    if (error instanceof EnvironmentError) {
      throw error;
    }
    logger.error(`Failed to delete environment: ${name}`, error);
    throw new EnvironmentError(`Failed to delete environment '${name}'`);
  }
}

/**
 * Get all variables in an environment
 */
export async function getAllVariables(
  environmentName: string = DEFAULT_ENVIRONMENT
): Promise<Array<z.infer<typeof StoredEnvironmentVariableSchema>>> {
  try {
    const environment = await getEnvironment(environmentName);
    
    // Return variables with decrypted values for non-secrets
    return environment.variables.map(variable => {
      const result = { ...variable };
      
      // Don't decrypt values for API response to protect secrets
      // Real decryption would happen on actual use, not listing
      if (result.is_secret) {
        result.value = '[SECRET]';
      }
      
      return result;
    });
  } catch (error) {
    if (error instanceof EnvironmentError) {
      throw error;
    }
    logger.error(`Failed to get variables for environment '${environmentName}'`, error);
    throw new EnvironmentError(`Failed to get variables for environment '${environmentName}'`);
  }
}

/**
 * Get variable by name (including decrypted secrets)
 */
export async function getVariable(
  name: string,
  environmentName: string = DEFAULT_ENVIRONMENT
): Promise<string> {
  try {
    const environment = await getEnvironment(environmentName);
    
    // Find the variable
    const variable = environment.variables.find(v => v.name === name);
    if (!variable) {
      throw new EnvironmentError(`Variable '${name}' not found in environment '${environmentName}'`);
    }
    
    // Decrypt if needed
    if (variable.is_secret && variable.encrypted) {
      return decryptValue(variable.value);
    }
    
    return variable.value;
  } catch (error) {
    if (error instanceof EnvironmentError) {
      throw error;
    }
    logger.error(`Failed to get variable '${name}' from environment '${environmentName}'`, error);
    throw new EnvironmentError(`Failed to get variable '${name}' from environment '${environmentName}'`);
  }
}

/**
 * Set a variable in an environment
 */
export async function setVariable(
  name: string,
  value: string,
  isSecret: boolean = false,
  environmentName: string = DEFAULT_ENVIRONMENT
): Promise<void> {
  try {
    // First ensure the environment exists
    let environment: StoredEnvironment;
    try {
      environment = await getEnvironment(environmentName);
    } catch (error) {
      if (error instanceof EnvironmentError && error.message.includes('not found')) {
        // Create the environment if it doesn't exist
        environment = await createNewEnvironment(environmentName);
      } else {
        throw error;
      }
    }
    
    // Find if variable already exists
    const existingIndex = environment.variables.findIndex(v => v.name === name);
    
    // Prepare the variable - encrypt if it's a secret
    let variableValue = value;
    let encrypted = false;
    
    if (isSecret) {
      variableValue = encryptValue(value);
      encrypted = true;
    }
    
    const variable: z.infer<typeof StoredEnvironmentVariableSchema> = {
      name,
      value: variableValue,
      is_secret: isSecret,
      encrypted
    };
    
    // Update or add the variable
    if (existingIndex >= 0) {
      environment.variables[existingIndex] = variable;
    } else {
      environment.variables.push(variable);
    }
    
    // Update modified timestamp
    environment.modified = new Date().toISOString();
    
    // Save the updated environment
    const filePath = getEnvironmentFilePath(sanitizeStorageName(environmentName));
    await writeJsonFile(filePath, environment);
    
    logger.info(`Set variable '${name}' in environment '${environmentName}'`);
  } catch (error) {
    if (error instanceof EnvironmentError) {
      throw error;
    }
    logger.error(`Failed to set variable '${name}' in environment '${environmentName}'`, error);
    throw new EnvironmentError(`Failed to set variable '${name}' in environment '${environmentName}'`);
  }
}

/**
 * Delete a variable from an environment
 */
export async function deleteVariable(
  name: string,
  environmentName: string = DEFAULT_ENVIRONMENT
): Promise<void> {
  try {
    const environment = await getEnvironment(environmentName);
    
    // Find the variable
    const existingIndex = environment.variables.findIndex(v => v.name === name);
    if (existingIndex === -1) {
      throw new EnvironmentError(`Variable '${name}' not found in environment '${environmentName}'`);
    }
    
    // Remove the variable
    environment.variables.splice(existingIndex, 1);
    
    // Update modified timestamp
    environment.modified = new Date().toISOString();
    
    // Save the updated environment
    const filePath = getEnvironmentFilePath(sanitizeStorageName(environmentName));
    await writeJsonFile(filePath, environment);
    
    logger.info(`Deleted variable '${name}' from environment '${environmentName}'`);
  } catch (error) {
    if (error instanceof EnvironmentError) {
      throw error;
    }
    logger.error(`Failed to delete variable '${name}' from environment '${environmentName}'`, error);
    throw new EnvironmentError(`Failed to delete variable '${name}' from environment '${environmentName}'`);
  }
}

/**
 * Get all variables as a flat key-value object for variable substitution
 */
export async function getVariablesForSubstitution(
  environmentName: string = DEFAULT_ENVIRONMENT
): Promise<Record<string, string>> {
  try {
    const environment = await getEnvironment(environmentName);
    
    // Create a flat key-value object with decrypted values
    const variables: Record<string, string> = {};
    
    for (const variable of environment.variables) {
      let value = variable.value;
      
      // Decrypt if needed
      if (variable.is_secret && variable.encrypted) {
        try {
          value = decryptValue(value);
        } catch (error) {
          logger.error(`Failed to decrypt variable '${variable.name}'`, error);
          // Skip this variable if decryption fails
          continue;
        }
      }
      
      variables[variable.name] = value;
    }
    
    return variables;
  } catch (error) {
    if (error instanceof EnvironmentError) {
      throw error;
    }
    logger.error(`Failed to get variables for substitution from environment '${environmentName}'`, error);
    throw new EnvironmentError(`Failed to get variables for substitution from environment '${environmentName}'`);
  }
}

// Function missing from filesytem-client - add this to maintain integrity
import { deleteFile } from './filesystem-client.js';