/**
 * Logger utility for the Postmancer MCP server
 */

/**
 * Log levels for the server
 */
export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error'
}

/**
 * Current log level - can be set via environment variable
 */
let currentLogLevel: LogLevel = LogLevel.INFO;

// Initialize log level from environment variable if available
if (process.env.LOG_LEVEL) {
  const envLevel = process.env.LOG_LEVEL.toLowerCase();
  if (Object.values(LogLevel).includes(envLevel as LogLevel)) {
    currentLogLevel = envLevel as LogLevel;
  }
}

/**
 * Log level priorities (higher number = more important)
 */
const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
  [LogLevel.DEBUG]: 0,
  [LogLevel.INFO]: 1,
  [LogLevel.WARN]: 2,
  [LogLevel.ERROR]: 3
};

/**
 * Check if a log level should be displayed based on current settings
 */
function shouldLog(level: LogLevel): boolean {
  return LOG_LEVEL_PRIORITY[level] >= LOG_LEVEL_PRIORITY[currentLogLevel];
}

/**
 * Set the current log level
 */
export function setLogLevel(level: LogLevel): void {
  currentLogLevel = level;
}

/**
 * Get the current log level
 */
export function getLogLevel(): LogLevel {
  return currentLogLevel;
}

/**
 * Format a log message with timestamp and level
 */
function formatLogMessage(level: LogLevel, message: string, data?: any): string {
  const timestamp = new Date().toISOString();
  let formattedMessage = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
  
  if (data) {
    try {
      const dataStr = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
      formattedMessage += `\n${dataStr}`;
    } catch (error) {
      formattedMessage += '\n[Error serializing data]';
    }
  }
  
  return formattedMessage;
}

/**
 * Log a debug message
 */
export function debug(message: string, data?: any): void {
  if (shouldLog(LogLevel.DEBUG)) {
    console.error(formatLogMessage(LogLevel.DEBUG, message, data));
  }
}

/**
 * Log an info message
 */
export function info(message: string, data?: any): void {
  if (shouldLog(LogLevel.INFO)) {
    console.error(formatLogMessage(LogLevel.INFO, message, data));
  }
}

/**
 * Log a warning message
 */
export function warn(message: string, data?: any): void {
  if (shouldLog(LogLevel.WARN)) {
    console.error(formatLogMessage(LogLevel.WARN, message, data));
  }
}

/**
 * Log an error message
 */
export function error(message: string, data?: any): void {
  if (shouldLog(LogLevel.ERROR)) {
    console.error(formatLogMessage(LogLevel.ERROR, message, data));
  }
}

/**
 * Log an error object with stack trace
 */
export function logError(err: Error, message?: string): void {
  if (shouldLog(LogLevel.ERROR)) {
    const errorMessage = message || err.message;
    console.error(formatLogMessage(LogLevel.ERROR, errorMessage, {
      name: err.name,
      message: err.message,
      stack: err.stack
    }));
  }
}

// Export a default logger object
export default {
  debug,
  info,
  warn,
  error,
  logError,
  setLogLevel,
  getLogLevel,
  LogLevel
};