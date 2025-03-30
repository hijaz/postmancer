/**
 * Zod schemas for the Postmancer MCP server
 */

import { z } from "zod";

/**
 * HTTP methods supported by the REST client
 */
export const HttpMethodSchema = z.enum([
  "GET", 
  "POST", 
  "PUT", 
  "DELETE", 
  "PATCH", 
  "HEAD", 
  "OPTIONS"
]);

export type HttpMethod = z.infer<typeof HttpMethodSchema>;

/**
 * Base HTTP request schema
 */
export const HttpRequestSchema = z.object({
  url: z.string().url(),
  method: HttpMethodSchema,
  headers: z.record(z.string()).optional(),
  body: z.string().optional(),
  query_params: z.record(z.string()).optional(),
  timeout: z.number().positive().optional(),
});

export type HttpRequest = z.infer<typeof HttpRequestSchema>;

/**
 * Authentication types supported by the REST client
 */
export const AuthTypeSchema = z.enum([
  "basic",
  "bearer",
  "oauth2",
  "api_key",
  "custom"
]);

export type AuthType = z.infer<typeof AuthTypeSchema>;

/**
 * Basic authentication schema
 */
export const BasicAuthSchema = z.object({
  type: z.literal("basic"),
  username: z.string(),
  password: z.string(),
});

/**
 * Bearer token authentication schema
 */
export const BearerAuthSchema = z.object({
  type: z.literal("bearer"),
  token: z.string(),
});

/**
 * API key authentication schema
 */
export const ApiKeyAuthSchema = z.object({
  type: z.literal("api_key"),
  key: z.string(),
  value: z.string(),
  in: z.enum(["header", "query"]),
  name: z.string(),
});

/**
 * OAuth2 flow types
 */
export const OAuth2FlowSchema = z.enum([
  "authorization_code",
  "client_credentials",
  "password",
  "implicit"
]);

/**
 * OAuth2 authentication schema
 */
export const OAuth2AuthSchema = z.object({
  type: z.literal("oauth2"),
  // Token fields
  token: z.string().optional(),
  token_type: z.enum(["bearer"]).default("bearer"),
  // OAuth2 configuration fields
  client_id: z.string(),
  authorization_url: z.string().url(),
  token_url: z.string().url(),
  redirect_uri: z.string().url(),
  flow: OAuth2FlowSchema,
  client_secret: z.string().optional(),
  scope: z.string().optional(),
});

/**
 * Custom authentication schema
 */
export const CustomAuthSchema = z.object({
  type: z.literal("custom"),
  headers: z.record(z.string()),
});

/**
 * Combined authentication schema
 */
export const AuthSchema = z.object({
  type: z.enum(["basic", "bearer", "oauth2", "api_key", "custom"]),
  // Basic auth fields
  username: z.string().optional(),
  password: z.string().optional(),
  // Bearer auth fields
  token: z.string().optional(),
  token_type: z.enum(["bearer"]).optional(),
  // API key auth fields
  key: z.string().optional(),
  value: z.string().optional(),
  in: z.enum(["header", "query"]).optional(),
  name: z.string().optional(),
  // OAuth2 fields
  client_id: z.string().optional(),
  authorization_url: z.string().url().optional(),
  token_url: z.string().url().optional(),
  redirect_uri: z.string().url().optional(),
  flow: z.enum(["authorization_code", "client_credentials", "password", "implicit"]).optional(),
  client_secret: z.string().optional(),
  scope: z.string().optional(),
  // Custom auth fields
  headers: z.record(z.string()).optional(),
}).refine(
  (data) => {
    switch (data.type) {
      case "basic":
        return !!data.username && !!data.password;
      case "bearer":
        return !!data.token;
      case "api_key":
        return !!data.key && !!data.value && !!data.in && !!data.name;
      case "oauth2":
        return !!data.client_id && !!data.authorization_url && !!data.token_url && !!data.redirect_uri && !!data.flow;
      case "custom":
        return !!data.headers;
      default:
        return false;
    }
  },
  {
    message: "Invalid authentication configuration",
    path: ["type"],
  }
);

export type Auth = z.infer<typeof AuthSchema>;

/**
 * Enhanced HTTP request schema with authentication
 */
export const EnhancedHttpRequestSchema = HttpRequestSchema.extend({
  auth: AuthSchema.optional(),
});

export type EnhancedHttpRequest = z.infer<typeof EnhancedHttpRequestSchema>;

/**
 * HTTP response schema
 */
export const HttpResponseSchema = z.object({
  status: z.number(),
  statusText: z.string(),
  headers: z.record(z.string()),
  body: z.string().or(z.any()),
  contentType: z.string().optional(),
});

export type HttpResponse = z.infer<typeof HttpResponseSchema>;

/**
 * Collection request schema for saving requests
 */
export const CollectionRequestSchema = z.object({
  collection_name: z.string(),
  request_name: z.string(),
  request: EnhancedHttpRequestSchema,
  description: z.string().optional(),
});

export type CollectionRequest = z.infer<typeof CollectionRequestSchema>;

/**
 * Environment variable schema
 */
export const EnvironmentVariableSchema = z.object({
  name: z.string(),
  value: z.string(),
  is_secret: z.boolean().default(false),
});

export type EnvironmentVariable = z.infer<typeof EnvironmentVariableSchema>;

/**
 * Test operation schema for response validation
 */
export const TestOperationSchema = z.enum([
  "equals",
  "not_equals",
  "contains",
  "not_contains",
  "greater_than",
  "less_than",
  "matches_regex",
  "exists",
  "not_exists",
  "is_null",
  "is_not_null",
]);

export type TestOperation = z.infer<typeof TestOperationSchema>;

/**
 * Test schema for running tests on responses
 */
export const TestSchema = z.object({
  name: z.string(),
  target: z.string(), // JSONPath or header name
  operation: TestOperationSchema,
  expected: z.any().optional(),
  target_type: z.enum(["body", "header", "status"]).default("body"),
});

export type Test = z.infer<typeof TestSchema>;