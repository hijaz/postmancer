[![MseeP.ai Security Assessment Badge](https://mseep.net/pr/hijaz-postmancer-badge.png)](https://mseep.ai/app/hijaz-postmancer)

# Postmancer

![Postmancer](postmancer.jpg)

A standalone MCP server for API testing and management, allowing AI assistants to interact with RESTful APIs through natural language.

## Overview

Postmancer is an MCP (Model Context Protocol) server that enables AI assistants like Claude to make HTTP requests, manage collections of API endpoints, and test API responses. It provides similar functionality to tools like Postman or Insomnia but designed specifically for AI assistants.

## Features

- Make HTTP requests to any REST API
- Save and organize requests in collections
- Set and use environment variables with variable substitution
- Multiple authentication methods (Basic, Bearer, API Key, OAuth2)
- Request/response history and testing

## Quick Start

### Installation

```bash
# Install globally
npm install -g postmancer

# Or run directly with npx
npx postmancer
```

### Using with Claude Desktop

Add this to your Claude Desktop configuration file:
- Windows: `%USERPROFILE%\.claude\claude_desktop_config.json`
- macOS/Linux: `~/.claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "postmancer": {
      "command": "npx",
      "args": ["-y", "postmancer"],
      "env": {
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

### Using with Docker

```bash
docker run -i --rm \
  --mount type=bind,src=/path/to/collections,dst=/data/collections \
  postmancer
```

## Available Tools

Postmancer provides the following tools to AI assistants:

1. **http_request** - Send HTTP requests to any URL
2. **list_collections** - View all your saved API collections
3. **list_requests** - View all requests in a collection
4. **save_request** - Save a request to a collection
5. **request_from_collection** - Execute a saved request
6. **set_environment_variable** - Set variables for request templates
7. **get_environment_variables** - View all environment variables

## Configuration

Configure Postmancer with these environment variables:

- `COLLECTIONS_PATH`: Path to store collections (default: ~/.postmancer)
- `LOG_LEVEL`: Logging level (debug, info, warn, error) (default: info)
- `POSTMANCER_ENCRYPTION_KEY`: Secret key used to encrypt credentials and tokens (generates a random key if not provided)
- `ENCRYPTION_KEY`: Secret key used to encrypt environment variables marked as secrets (uses default key if not provided)

For security in production environments, it's strongly recommended to set these encryption keys rather than using the defaults.

## License

MIT