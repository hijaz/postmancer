#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, Tool } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import logger from "./logger.js";
import { PostmancerError, NotImplementedError, ValidationError, CollectionError, EnvironmentError } from "./errors.js";
import { EnhancedHttpRequestSchema, HttpResponseSchema, CollectionRequestSchema } from "./schemas.js";
import { makeRequest, makeRequestWithRetry } from "./http-client.js";
import { zodToJsonSchema } from "zod-to-json-schema";
import { initializeStorage } from "./filesystem-client.js";
import * as collectionService from "./collection-service.js";
import * as environmentService from "./environment-service.js";
import { substituteVariables } from "./storage.js";

// Initialize storage
initializeStorage().catch(error => {
  logger.error("Failed to initialize storage", error);
  process.exit(1);
});

// Create tool schema for the http_request tool
const HttpRequestToolSchema = EnhancedHttpRequestSchema.extend({
  retry: z.boolean().optional().default(false),
  max_retries: z.number().positive().optional().default(3),
  retry_delay: z.number().positive().optional().default(1000),
});

// Schema for listing collections
const ListCollectionsSchema = z.object({});

// Schema for listing requests in a collection
const ListRequestsSchema = z.object({
  collection_name: z.string().min(1),
});

// Schema for saving a request to a collection
const SaveRequestSchema = z.object({
  collection_name: z.string().min(1),
  request_name: z.string().min(1),
  request: EnhancedHttpRequestSchema,
  description: z.string().optional(),
});

// Schema for retrieving a request from a collection
const RequestFromCollectionSchema = z.object({
  collection_name: z.string().min(1),
  request_name: z.string().min(1),
  environment_name: z.string().optional(),
  execute: z.boolean().optional().default(true),
});

// Schema for managing environment variables
const SetEnvironmentVariableSchema = z.object({
  name: z.string().min(1),
  value: z.string(),
  is_secret: z.boolean().optional().default(false),
  environment_name: z.string().optional(),
});

// Schema for getting environment variables
const GetEnvironmentVariablesSchema = z.object({
  environment_name: z.string().optional(),
});

// Initialize the server - simpler initialization following memory server pattern
const server = new Server({
  name: "postmancer",
  version: "0.1.0",
}, {
  capabilities: {
    tools: {},
  },
});

// Log startup information
logger.info("Postmancer MCP Server initializing");

// Define tools (List Tools handler)
server.setRequestHandler(ListToolsRequestSchema, async () => {
  logger.debug("Listing available tools");
  
  // Log the JSON schema for debugging
  const httpRequestSchema = zodToJsonSchema(HttpRequestToolSchema);
  logger.debug("HTTP Request Schema:", JSON.stringify(httpRequestSchema, null, 2));
  
  return {
    tools: [
      {
        name: "http_request",
        description: "Sends HTTP requests to specified URLs with optional authentication, headers, and body",
        inputSchema: { type: "object", ...httpRequestSchema } as { type: "object"; [k: string]: unknown },
      },
      {
        name: "list_collections",
        description: "Lists all available request collections",
        inputSchema: { type: "object", ...zodToJsonSchema(ListCollectionsSchema) } as { type: "object"; [k: string]: unknown },
      },
      {
        name: "list_requests",
        description: "Lists all requests in a specified collection",
        inputSchema: { type: "object", ...zodToJsonSchema(ListRequestsSchema) } as { type: "object"; [k: string]: unknown },
      },
      {
        name: "save_request",
        description: "Saves an HTTP request to a collection for future use",
        inputSchema: { type: "object", ...zodToJsonSchema(SaveRequestSchema) } as { type: "object"; [k: string]: unknown },
      },
      {
        name: "request_from_collection",
        description: "Retrieves and optionally executes a request from a collection",
        inputSchema: { type: "object", ...zodToJsonSchema(RequestFromCollectionSchema) } as { type: "object"; [k: string]: unknown },
      },
      {
        name: "set_environment_variable",
        description: "Sets an environment variable for use in HTTP requests",
        inputSchema: { type: "object", ...zodToJsonSchema(SetEnvironmentVariableSchema) } as { type: "object"; [k: string]: unknown },
      },
      {
        name: "get_environment_variables",
        description: "Retrieves all environment variables from the specified environment",
        inputSchema: { type: "object", ...zodToJsonSchema(GetEnvironmentVariablesSchema) } as { type: "object"; [k: string]: unknown },
      }
    ],
  };
});

// Implement tool execution (Call Tool handler)
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  logger.info(`Tool execution requested: ${name}`, args);
  
  try {
    // Handle the http_request tool
    if (name === "http_request") {
      const requestArgs = HttpRequestToolSchema.parse(args);
      const { retry, max_retries, retry_delay, ...httpRequest } = requestArgs;
      
      let response: z.infer<typeof HttpResponseSchema>;
      
      if (retry) {
        response = await makeRequestWithRetry(httpRequest, max_retries, retry_delay);
      } else {
        response = await makeRequest(httpRequest);
      }
      
      // Format the response for display
      const formattedResponse = formatResponseForDisplay(response);
      
      return {
        content: [
          {
            type: "text",
            text: formattedResponse
          }
        ]
      };
    }
    // Handle list_collections tool
    else if (name === "list_collections") {
      // Validate arguments (empty object is valid)
      ListCollectionsSchema.parse(args);
      
      // Get collections
      const collections = await collectionService.listCollections();
      
      // Format output
      let output = "Collections:\n\n";
      
      if (collections.length === 0) {
        output += "No collections found.";
      } else {
        collections.forEach(collection => {
          output += `- ${collection.name}`;
          if (collection.description) {
            output += `: ${collection.description}`;
          }
          output += "\n";
        });
      }
      
      return {
        content: [
          {
            type: "text",
            text: output
          }
        ]
      };
    }
    // Handle list_requests tool
    else if (name === "list_requests") {
      // Validate arguments
      const { collection_name } = ListRequestsSchema.parse(args);
      
      // Get requests for the collection
      const requests = await collectionService.listRequests(collection_name);
      
      // Format output
      let output = `Requests in collection '${collection_name}':\n\n`;
      
      if (requests.length === 0) {
        output += "No requests found in this collection.";
      } else {
        requests.forEach(request => {
          output += `- ${request.name}`;
          if (request.description) {
            output += `: ${request.description}`;
          }
          output += "\n";
        });
      }
      
      return {
        content: [
          {
            type: "text",
            text: output
          }
        ]
      };
    }
    // Handle save_request tool
    else if (name === "save_request") {
      // Validate arguments
      const { collection_name, request_name, request, description } = SaveRequestSchema.parse(args);
      
      // Ensure collection exists or create it
      try {
        await collectionService.getCollection(collection_name);
      } catch (error) {
        if (error instanceof CollectionError && error.message.includes('not found')) {
          await collectionService.createNewCollection(collection_name);
        } else {
          throw error;
        }
      }
      
      // Save the request
      await collectionService.saveRequest(collection_name, request_name, request, description);
      
      return {
        content: [
          {
            type: "text",
            text: `Successfully saved request '${request_name}' to collection '${collection_name}'.`
          }
        ]
      };
    }
    // Handle request_from_collection tool
    else if (name === "request_from_collection") {
      // Validate arguments
      const { collection_name, request_name, environment_name, execute } = RequestFromCollectionSchema.parse(args);
      
      // Get the request from the collection
      const request = await collectionService.getRequest(collection_name, request_name);
      
      // If not executing, just show the request details
      if (!execute) {
        const requestJSON = JSON.stringify(request, null, 2);
        return {
          content: [
            {
              type: "text",
              text: `Request '${request_name}' from collection '${collection_name}':\n\n${requestJSON}`
            }
          ]
        };
      }
      
      // Otherwise execute the request with environment substitution if needed
      let requestToExecute = { ...request };
      
      if (environment_name) {
        // Get variables for substitution
        const variables = await environmentService.getVariablesForSubstitution(environment_name);
        
        // Perform variable substitution
        requestToExecute = substituteVariables(requestToExecute, variables);
      }
      
      // Execute the request
      const response = await makeRequest(requestToExecute);
      
      // Format the response
      const formattedResponse = formatResponseForDisplay(response);
      
      return {
        content: [
          {
            type: "text",
            text: `Executed request '${request_name}' from collection '${collection_name}':\n\n${formattedResponse}`
          }
        ]
      };
    }
    // Handle set_environment_variable tool
    else if (name === "set_environment_variable") {
      // Validate arguments
      const { name: varName, value, is_secret, environment_name } = SetEnvironmentVariableSchema.parse(args);
      
      // Set the variable
      await environmentService.setVariable(
        varName, 
        value,
        is_secret, 
        environment_name || environmentService.DEFAULT_ENVIRONMENT
      );
      
      const envName = environment_name || environmentService.DEFAULT_ENVIRONMENT;
      
      return {
        content: [
          {
            type: "text",
            text: `Successfully set environment variable '${varName}' in environment '${envName}'.`
          }
        ]
      };
    }
    // Handle get_environment_variables tool
    else if (name === "get_environment_variables") {
      // Validate arguments
      const { environment_name } = GetEnvironmentVariablesSchema.parse(args);
      
      // Get variables
      const envName = environment_name || environmentService.DEFAULT_ENVIRONMENT;
      const variables = await environmentService.getAllVariables(envName);
      
      // Format output
      let output = `Environment variables in '${envName}':\n\n`;
      
      if (variables.length === 0) {
        output += "No variables found in this environment.";
      } else {
        variables.forEach(variable => {
          output += `- ${variable.name}: `;
          if (variable.is_secret) {
            output += "[SECRET]";
          } else {
            output += variable.value;
          }
          output += "\n";
        });
      }
      
      return {
        content: [
          {
            type: "text",
            text: output
          }
        ]
      };
    }
    else {
      // No other tools implemented yet
      throw new NotImplementedError(`Tool ${name} not yet implemented`);
    }
  } catch (err) {
    if (err instanceof PostmancerError) {
      logger.error(`Error executing tool ${name}: ${err.message}`);
      return {
        content: [
          {
            type: "text",
            text: `Error: ${err.message}`
          }
        ]
      };
    } else if (err instanceof z.ZodError) {
      // Handle validation errors
      const validationErrors = err.errors.map(e => `${e.path.join('.')}: ${e.message}`).join(', ');
      logger.error(`Validation error: ${validationErrors}`);
      return {
        content: [
          {
            type: "text",
            text: `Validation error: ${validationErrors}`
          }
        ]
      };
    } else {
      // Unexpected error
      const error = err as Error;
      logger.error(`Unexpected error executing tool ${name}: ${error.message}`);
      return {
        content: [
          {
            type: "text",
            text: `Unexpected error: ${error.message}`
          }
        ]
      };
    }
  }
});

/**
 * Format the HTTP response for display to the user
 * Handles various response types including binary data
 */
function formatResponseForDisplay(response: z.infer<typeof HttpResponseSchema>): string {
  const { status, statusText, headers, body, contentType } = response;
  
  // Start with the status line
  let formatted = `HTTP ${status} ${statusText}\n\n`;
  
  // Add headers
  formatted += "Headers:\n";
  Object.entries(headers).forEach(([key, value]) => {
    formatted += `${key}: ${value}\n`;
  });
  
  // Add body with appropriate formatting
  formatted += "\nBody:\n";
  
  // Handle different body formats
  if (body === null || body === undefined) {
    formatted += "[Empty Body]";
  }
  // Handle binary data
  else if (typeof body === 'object' && body.type === 'binary' && body.encoding) {
    if (body.encoding === 'base64') {
      formatted += `[Binary data, ${body.size || 'unknown'} bytes, base64 encoded]`;
      // Optionally show a preview for very small binary data
      if (body.data && typeof body.data === 'string' && body.data.length < 100) {
        formatted += `\nPreview: ${body.data}`;
      }
    } else {
      formatted += `[Binary data, ${body.size || 'unknown'} bytes]`;
    }
  }
  // Handle JSON
  else if (contentType && contentType.includes('application/json')) {
    try {
      // For JSON, pretty print it
      const jsonBody = typeof body === 'string' ? JSON.parse(body) : body;
      formatted += JSON.stringify(jsonBody, null, 2);
    } catch (error) {
      // If parsing fails, just return the raw body
      formatted += typeof body === 'string' ? body : JSON.stringify(body);
    }
  } 
  // Handle XML
  else if (contentType && (contentType.includes('application/xml') || contentType.includes('text/xml'))) {
    // Just display the XML as is for now
    formatted += typeof body === 'string' ? body : String(body);
  }
  // Handle HTML
  else if (contentType && contentType.includes('text/html')) {
    // For HTML, add a note about the length and a preview
    const htmlString = typeof body === 'string' ? body : String(body);
    const previewLength = Math.min(200, htmlString.length);
    
    formatted += `[HTML content, ${htmlString.length} characters]\n`;
    formatted += `Preview: ${htmlString.substring(0, previewLength)}${htmlString.length > previewLength ? '...' : ''}`;
  }
  // Handle plain text
  else if (contentType && contentType.includes('text/plain')) {
    formatted += typeof body === 'string' ? body : String(body);
  }
  // Handle other types
  else if (typeof body === 'object') {
    try {
      formatted += JSON.stringify(body, null, 2);
    } catch (error) {
      formatted += "[Object: cannot display]";
    }
  } else {
    formatted += typeof body === 'string' ? body : String(body);
  }
  
  return formatted;
}

// Handle errors and exit
process.on('SIGINT', () => {
  logger.info('Received SIGINT, shutting down');
  process.exit(0);
});

process.on('uncaughtException', (err) => {
  logger.error(`Uncaught exception: ${err.message}`);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  if (reason instanceof Error) {
    logger.error(`Unhandled promise rejection: ${reason.message}`);
  } else {
    logger.error('Unhandled promise rejection', reason);
  }
  process.exit(1);
});

// Simple clean main function following memory server pattern
async function main() {
  try {
    // Ensure default environment exists
    await environmentService.ensureDefaultEnvironment();
    
    // Connect to transport
    const transport = new StdioServerTransport();
    await server.connect(transport);
    
    logger.info('Postmancer MCP Server running on stdio');
  } catch (error) {
    if (error instanceof Error) {
      logger.error(`Failed to start server: ${error.message}`);
    } else {
      logger.error('Failed to start server with unknown error', error);
    }
    process.exit(1);
  }
}

// Call main directly at the end of the file
main().catch((error) => {
  console.error("Fatal error in main():", error);
  process.exit(1);
});
