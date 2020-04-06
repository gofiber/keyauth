### Install
```
go get -u github.com/gofiber/fiber
go get -u github.com/gofiber/keyauth
```
### Example
```go
package main

import (
  "github.com/gofiber/fiber"
  "github.com/gofiber/keyauth"
)

func main() {
  app := fiber.New()
  
  app.Use(keyauth.New(keyauth.Config{
    TokenLookup: "cookie:access_token",
    ContextKey: "my_token"
  }))
  
  app.Get("/", func(c *fiber.Ctx) {
    c.Send(c.Locals("my_token"))
  })
  
  app.Listen(3000)
}
```
### Test
```curl
curl -v --cookie "access_token=hello_world" http://localhost:3000
```