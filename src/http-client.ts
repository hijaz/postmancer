/**
 * HTTP client module for the Postmancer MCP server
 * This module handles making HTTP requests with appropriate validation, 
 * error handling, and security measures.
 */

import axios, { AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';
import { z } from 'zod';
import { HttpRequestSchema, EnhancedHttpRequestSchema, HttpResponseSchema, AuthSchema } from './schemas.js';
import { HttpRequestError, ValidationError, SecurityError } from './errors.js';
import logger from './logger.js';
import { getOAuth2Tokens, refreshOAuth2Tokens } from './credential-manager.js';

// Default timeout in milliseconds
const DEFAULT_TIMEOUT = 30000;

// Max size for request body (in bytes)
const MAX_REQUEST_SIZE = 10 * 1024 * 1024; // 10MB

/**
 * Apply authentication to the request config
 */
export async function applyAuthentication(
  config: AxiosRequestConfig, 
  auth: z.infer<typeof AuthSchema>,
  credentialId?: string
): Promise<AxiosRequestConfig> {
  const newConfig = { ...config };
  
  switch (auth.type) {
    case 'basic': {
      const { username, password } = auth;
      const authHeader = `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
      newConfig.headers = {
        ...newConfig.headers,
        'Authorization': authHeader
      };
      break;
    }
    case 'bearer': {
      const { token } = auth;
      newConfig.headers = {
        ...newConfig.headers,
        'Authorization': `Bearer ${token}`
      };
      break;
    }
    case 'api_key': {
      const { key, value, in: location, name } = auth;
      if (location === 'header') {
        newConfig.headers = {
          ...newConfig.headers,
          [name as string]: value
        };
      } else if (location === 'query') {
        newConfig.params = {
          ...newConfig.params,
          [name as string]: value
        };
      }
      break;
    }
    case 'oauth2': {
      let token = auth.token;
      
      // If no token is provided but we have a credential ID, try to get the token
      if (!token && credentialId) {
        const storedToken = getOAuth2Tokens(credentialId);
        if (storedToken) {
          token = storedToken.access_token;
        } else {
          // If no stored token, try to refresh
          const oauth2Config = {
            client_id: auth.client_id!,
            authorization_url: auth.authorization_url!,
            token_url: auth.token_url!,
            redirect_uri: auth.redirect_uri!,
            flow: auth.flow!,
            client_secret: auth.client_secret,
            scope: auth.scope
          };
          await refreshOAuth2Tokens(credentialId, oauth2Config);
          const refreshedToken = getOAuth2Tokens(credentialId);
          if (refreshedToken) {
            token = refreshedToken.access_token;
          }
        }
      }
      
      if (!token) {
        throw new SecurityError('No OAuth2 token available');
      }
      
      const tokenType = auth.token_type || 'bearer';
      newConfig.headers = {
        ...newConfig.headers,
        'Authorization': `${tokenType.charAt(0).toUpperCase() + tokenType.slice(1)} ${token}`
      };
      break;
    }
    case 'custom': {
      const { headers } = auth;
      newConfig.headers = {
        ...newConfig.headers,
        ...headers
      };
      break;
    }
  }
  
  return newConfig;
}

/**
 * Sanitize request headers to prevent security issues
 */
function sanitizeHeaders(headers: Record<string, string> = {}): Record<string, string> {
  const sanitized: Record<string, string> = {};
  
  // Remove any sensitive headers that might be used for SSRF or other attacks
  const blockedHeaders = ['host', 'referer', 'origin', 'x-forwarded-for', 'x-forwarded-host'];
  
  Object.entries(headers).forEach(([key, value]) => {
    const lowerKey = key.toLowerCase();
    if (!blockedHeaders.includes(lowerKey)) {
      sanitized[key] = value;
    } else {
      logger.warn(`Removed potentially unsafe header: ${key}`);
    }
  });
  
  return sanitized;
}

/**
 * Validate and prepare query parameters
 */
function prepareQueryParams(params: Record<string, string> = {}): Record<string, string> {
  // You could add additional validation here if needed
  return params;
}

/**
 * Format the request body based on content type
 */
function formatRequestBody(body: string | undefined, headers: Record<string, string> = {}): any {
  if (!body) return undefined;
  
  // Check body size
  if (body.length > MAX_REQUEST_SIZE) {
    throw new ValidationError(`Request body exceeds maximum size of ${MAX_REQUEST_SIZE / 1024 / 1024}MB`);
  }

  // Get content type from headers
  const contentType = headers['Content-Type'] || headers['content-type'] || 'application/json';
  
  if (contentType.includes('application/json')) {
    try {
      return JSON.parse(body);
    } catch (error) {
      throw new ValidationError('Invalid JSON in request body');
    }
  }
  
  // For other content types, return as is
  return body;
}

/**
 * Process the Axios response into our HttpResponse format
 * with improved content type detection and handling
 */
function processResponse(response: AxiosResponse): z.infer<typeof HttpResponseSchema> {
  // Extract basic response properties
  const { status, statusText, headers, data, config } = response;
  
  // Get content type
  const contentType = headers['content-type'] || '';
  
  // Process body based on content type
  let processedBody = data;
  
  // For binary data (if response type was arraybuffer or blob)
  if (
    (typeof data === 'object' && data instanceof ArrayBuffer) ||
    (typeof data === 'object' && typeof process === 'undefined' && typeof global.Blob !== 'undefined' && data instanceof global.Blob)
  ) {
    // Convert ArrayBuffer to base64 for transmission
    if (data instanceof ArrayBuffer) {
      const buffer = Buffer.from(data);
      processedBody = {
        type: 'binary',
        encoding: 'base64',
        data: buffer.toString('base64'),
        size: buffer.length
      };
    } else {
      // For Blob objects, we'd need to handle them appropriately
      processedBody = {
        type: 'binary',
        encoding: 'blob',
        size: data.size
      };
    }
  } 
  // For JSON responses
  else if (contentType.includes('application/json')) {
    // If the data is already parsed as JSON (object)
    if (typeof data === 'object') {
      processedBody = data;
    } 
    // If the data is a JSON string
    else if (typeof data === 'string') {
      try {
        processedBody = JSON.parse(data);
      } catch (e) {
        // If parsing fails, keep the original string
        processedBody = data;
      }
    }
  } 
  // For XML responses
  else if (contentType.includes('application/xml') || contentType.includes('text/xml')) {
    // Just keep as string for now, we could add XML parsing later
    processedBody = typeof data === 'string' ? data : String(data);
  } 
  // For HTML responses
  else if (contentType.includes('text/html')) {
    processedBody = typeof data === 'string' ? data : String(data);
  } 
  // For plain text
  else if (contentType.includes('text/plain')) {
    processedBody = typeof data === 'string' ? data : String(data);
  } 
  // For other types, keep as is
  else {
    processedBody = data;
  }
  
  // Create response object
  const httpResponse: z.infer<typeof HttpResponseSchema> = {
    status,
    statusText,
    headers: headers as Record<string, string>,
    body: processedBody,
    contentType
  };
  
  return httpResponse;
}

/**
 * Convert AxiosError to our HttpRequestError
 */
function handleRequestError(error: AxiosError): never {
  if (error.response) {
    // The request was made and the server responded with a status code
    // that falls out of the range of 2xx
    const { status, statusText, headers, data } = error.response;
    
    throw new HttpRequestError(
      `Request failed with status ${status}: ${statusText}`,
      status
    );
  } else if (error.request) {
    // The request was made but no response was received
    throw new HttpRequestError('No response received from server');
  } else {
    // Something happened in setting up the request that triggered an Error
    throw new HttpRequestError(`Error setting up request: ${error.message}`);
  }
}

/**
 * Make an HTTP request with proper validation, error handling, and security
 */
export async function makeRequest(
  request: z.infer<typeof EnhancedHttpRequestSchema>
): Promise<z.infer<typeof HttpResponseSchema>> {
  // Parse and validate the request with Zod
  const validatedRequest = EnhancedHttpRequestSchema.parse(request);
  
  // Validate URL for security
  const { url, method, headers = {}, body, query_params, auth, timeout = DEFAULT_TIMEOUT } = validatedRequest;
  
  // Build Axios request config
  let config: AxiosRequestConfig = {
    url,
    method,
    headers: sanitizeHeaders(headers),
    params: prepareQueryParams(query_params),
    timeout,
    validateStatus: () => true, // Don't throw errors for non-2xx status codes
  };
  
  // Add request body if provided
  if (body) {
    config.data = formatRequestBody(body, headers);
  }
  
  // Apply authentication if provided
  if (auth) {
    config = await applyAuthentication(config, auth);
  }
  
  // Log the request (redact sensitive info)
  logger.debug('Making HTTP request', {
    url,
    method,
    headers: sanitizeHeaders(headers),
    hasBody: !!body,
    params: query_params,
    hasAuth: !!auth
  });
  
  try {
    // Make the actual HTTP request
    const response = await axios(config);
    
    // Process and return the response
    const processedResponse = processResponse(response);
    
    // Log response (excluding potentially large body)
    logger.debug('Received HTTP response', {
      status: processedResponse.status,
      statusText: processedResponse.statusText,
      contentType: processedResponse.contentType,
      bodySize: JSON.stringify(processedResponse.body).length
    });
    
    return processedResponse;
  } catch (error) {
    if (axios.isAxiosError(error)) {
      handleRequestError(error);
    } else {
      // For non-Axios errors, rethrow
      throw error;
    }
  }
}

/**
 * Make a request with retries
 */
export async function makeRequestWithRetry(
  request: z.infer<typeof EnhancedHttpRequestSchema>,
  maxRetries: number = 3,
  retryDelay: number = 1000
): Promise<z.infer<typeof HttpResponseSchema>> {
  let lastError: Error | undefined;
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await makeRequest(request);
    } catch (error) {
      lastError = error as Error;
      
      // Only retry on certain error types (e.g., network errors, 5xx errors)
      if (error instanceof HttpRequestError) {
        const statusCode = error.statusCode;
        
        // Don't retry on 4xx errors (except 429 Too Many Requests)
        if (statusCode && statusCode >= 400 && statusCode < 500 && statusCode !== 429) {
          throw error;
        }
        
        logger.warn(`Request attempt ${attempt + 1} failed, retrying in ${retryDelay}ms`);
        await new Promise(resolve => setTimeout(resolve, retryDelay * Math.pow(2, attempt)));
      } else {
        // For other errors, don't retry
        throw error;
      }
    }
  }
  
  // If we got here, all retries failed
  throw lastError || new HttpRequestError('Request failed after multiple retries');
}