### Key Auth Middleware
Key auth middleware provides a key based authentication.

+ For valid key it calls the next handler.
+ For invalid key, it sends “401 - Unauthorized” response.
+ For missing key, it sends “400 - Bad Request” response

Special thanks and credits to [Echo](https://echo.labstack.com/middleware/key-auth)

### Install
```
go get -u github.com/gofiber/fiber
go get -u github.com/gofiber/keyauth
```

### Signature
```go
keyauth.New(config ...keyauth.Config) func(*fiber.Ctx)
```

### Config
| Property | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| Filter | `func(*fiber.Ctx) bool` | Defines a function to skip middleware. | `nil` |
| SuccessHandler | `func(*fiber.Ctx)` |  SuccessHandler defines a function which is executed for a valid key. | `nil` |
| ErrorHandler | `func(*fiber.Ctx, error)` | ErrorHandler defines a function which is executed for an invalid key. | `401 Invalid or expired API key` |
| KeyLookup | `string` | KeyLookup is a string in the form of `<source>:<name>` that is used. | `"header:Authorization"` |
| AuthScheme | `string` | AuthScheme to be used in the Authorization header. | `"Bearer"` |
| Validator | `func(string, *fiber.Ctx) (bool, error)` | Validator is a function to validate key. | `nil` |


### Example
```go
package main

import (
  "errors"
  "github.com/gofiber/fiber"
  "github.com/gofiber/keyauth"
)

type ApiKey struct {
	Id     int
	Name   string
	Secret string
	Key    string
}

func main() {
  app := fiber.New()

  // Unauthenticated route
  app.Get("/", accessible)

  // API Key Middleware
  app.Use(keyauth.New(keyauth.Config{
    KeyLookup: "query:api-key",
    Validator: apiKeyValidator,
  }))

  // Restricted Routes
  app.Get("/restricted", restricted)

  app.Listen(3000)
}

func accessible(c *fiber.Ctx) {
  c.Send("Accessible")
}

func restricted(c *fiber.Ctx) {
  client := c.Locals("client").(*ApiKey)
  name := client.Name
  c.Send("Welcome " + name)
}

func apiKeyValidator(key string, c *fiber.Ctx) (bool, error)  {
    apiKey := &ApiKey{
        Id: 1,
        Name: "app1",
        Secret: "secret1",
        Key: "123123123",
    }
    apiKeys := make([]*ApiKey, 0)
    apiKeys = append(apiKeys, apiKey)
    
    for _, k := range apiKeys {
        if k.Key == key {
            c.Locals("client", k)
            return true, nil
        }
    }
    return false, errors.New("Missing or not existing API Key")
}
```

### Test

_Request a restricted resource using the key in `api-key` query._
```
curl --location --request GET 'http://localhost:3000/restricted?api-key=123123123'
```
_Response_
```
Welcome app1
```