/**
 * Custom error classes for the Postmancer MCP server
 */

/**
 * Base error class for Postmancer server errors
 */
export class PostmancerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PostmancerError';
  }
}

/**
 * Error thrown when there's an issue with HTTP requests
 */
export class HttpRequestError extends PostmancerError {
  statusCode?: number;
  
  constructor(message: string, statusCode?: number) {
    super(message);
    this.name = 'HttpRequestError';
    this.statusCode = statusCode;
  }
}

/**
 * Error thrown when there's an issue with request validation
 */
export class ValidationError extends PostmancerError {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}

/**
 * Error thrown when there's an issue with collections
 */
export class CollectionError extends PostmancerError {
  constructor(message: string) {
    super(message);
    this.name = 'CollectionError';
  }
}

/**
 * Error thrown when there's an issue with environment variables
 */
export class EnvironmentError extends PostmancerError {
  constructor(message: string) {
    super(message);
    this.name = 'EnvironmentError';
  }
}

/**
 * Error thrown when an operation is not yet implemented
 */
export class NotImplementedError extends PostmancerError {
  constructor(message: string = 'This feature is not yet implemented') {
    super(message);
    this.name = 'NotImplementedError';
  }
}

/**
 * Error thrown when there's an issue with authentication
 */
export class AuthenticationError extends PostmancerError {
  constructor(message: string) {
    super(message);
    this.name = 'AuthenticationError';
  }
}

/**
 * Error thrown when there's a security-related issue
 */
export class SecurityError extends PostmancerError {
  constructor(message: string) {
    super(message);
    this.name = 'SecurityError';
  }
}

// For backward compatibility
export const RestClientError = PostmancerError;