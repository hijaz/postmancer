# Postmancer Examples

This document contains examples of how to use Postmancer with Claude or other AI assistants.

## Basic HTTP Requests

### Simple GET Request
```
Send a GET request to https://httpbin.org/get with a header named "X-Test" set to "hello-world"
```

### POST Request with JSON Body
```
Send a POST request to https://httpbin.org/post with this JSON body:
{
  "name": "John Doe",
  "email": "john@example.com"
}
```

## Working with Collections

### Creating a Collection
```
Create a collection called "API Testing"
```

### Saving a Request to a Collection
```
Save this request to the "API Testing" collection with the name "Basic Auth Test":
GET https://httpbin.org/basic-auth/user/pass
With Basic Auth username "user" and password "pass"
```

### Using a Saved Request
```
Run the "Basic Auth Test" request from the "API Testing" collection
```

## Working with Environment Variables

### Setting Variables
```
Set an environment variable called "base_url" with the value "https://api.github.com"
```

### Using Variables in Requests
```
Send a GET request to {{base_url}}/users/octocat
```

## Authentication Examples

### OAuth2 Example
```
Send a GET request to https://api.github.com/user with Bearer token "YOUR_TOKEN"
```

### API Key Example
```
Send a GET request to https://api.weatherapi.com/v1/current.json with query parameter "key" set to "YOUR_API_KEY" and "q" set to "London"
```