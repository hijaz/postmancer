```json
{
  "mcpServers": {
    "postmancer": {
      "command": "npx",
      "args": ["-y", "postmancer"],
      "env": {
        "LOG_LEVEL": "info",
        "COLLECTIONS_PATH": "C:/Users/username/.postmancer"
      }
    }
  }
}
```

1. Save this configuration to your Claude Desktop configuration file:
   - Windows: `%USERPROFILE%\.claude\claude_desktop_config.json`
   - macOS/Linux: `~/.claude/claude_desktop_config.json`

2. Restart Claude Desktop

3. Now you can use Postmancer with Claude! Try asking:
   - "Make a GET request to https://httpbin.org/get"
   - "Create a collection called 'GitHub' and save a request to get a user's repositories"
   - "Set an environment variable called 'base_url' with the value 'https://api.github.com'"