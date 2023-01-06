# Key Authentication

![Release](https://img.shields.io/github/release/gofiber/keyauth.svg)
[![Discord](https://img.shields.io/badge/discord-join%20channel-7289DA)](https://gofiber.io/discord)
![Test](https://github.com/gofiber/keyauth/workflows/Test/badge.svg)
![Security](https://github.com/gofiber/keyauth/workflows/Security/badge.svg)
![Linter](https://github.com/gofiber/keyauth/workflows/Linter/badge.svg)

Special thanks to [József Sallai](https://github.com/jozsefsallai) & [Ray Mayemir](https://github.com/raymayemir)

### Install
```
go get -u github.com/gofiber/fiber/v2
go get -u github.com/gofiber/keyauth/v2
```
### Example
```go
package main

import (
  "github.com/gofiber/fiber/v2"
  "github.com/gofiber/keyauth/v2"
)

var (
  APIKey = "correct horse battery staple"
)

func validateAPIKey(c *fiber.Ctx, key string) (bool, error) {
	if key == APIKey {
		return true, nil
	}
	return false, keyauth.ErrMissingOrMalformedAPIKey
}

func main() {
  app := fiber.New()
  
  // note that the keyauth middleware needs to be defined before the routes are defined!
  app.Use(keyauth.New(keyauth.Config{
    KeyLookup:  "cookie:access_token",
    Validator:  validateAPIKey,
  }))

  app.Get("/", func(c *fiber.Ctx) error {
    return c.SendString("Successfully authenticated!")
  })

  app.Listen(":3000")
}
```

### Test

```bash
# No api-key specified -> 400 missing 
curl http://localhost:3000
#> missing or malformed API Key

curl --cookie "access_token=correct horse battery staple" http://localhost:3000
#> Successfully authenticated!

curl --cookie "access_token=Clearly A Wrong Key" http://localhost:3000
#>  missing or malformed API Key
```

For a more detailed example, see also the [`github.com/gofiber/recipes`](https://github.com/gofiber/recipes) repository and specifically the `fiber-envoy-extauthz` repository and the [`keyauth example`](https://github.com/gofiber/recipes/blob/master/fiber-envoy-extauthz/authz/main.go) code.


### Authenticate only certain endpoints

If you want to authenticate only certain endpoints, you can use the `Config` of keyauth and apply a filter function (eg. `authFilter`) like so

```go
package main

import (
  "github.com/gofiber/fiber/v2"
  "github.com/gofiber/keyauth/v2"
)
var (
  APIKey = "correct horse battery staple"
)

func validateAPIKey(c *fiber.Ctx, key string) (bool, error) {
	if key == APIKey {
		return true, nil
	}
	return false, keyauth.ErrMissingOrMalformedAPIKey
}

func authFilter(c *fiber.Ctx) bool {
  protectedURLs := map[string]interface{}{"/authenticated": nil, "/auth2": nil}
  _, exists := protectedURLs[c.OriginalURL()]
  return !exists
}

func main() {
  app := fiber.New()

  app.Use(keyauth.New(keyauth.Config{
    Filter: authFilter,
    KeyLookup:  "cookie:access_token",
    Validator:  validateAPIKey,
  }))

  app.Get("/", func(c *fiber.Ctx) error {
    return c.SendString("Welcome")
  })
  app.Get("/authenticated", func(c *fiber.Ctx) error {
    return c.SendString("Successfully authenticated!")
  })
  app.Get("/auth2", func(c *fiber.Ctx) error {
    return c.SendString("Successfully authenticated 2!")
  })

  app.Listen(":3000")
}
```

Which results in this

```bash
# / does not need to be authenticated
curl http://localhost:3000
#> Welcome

# /authenticated needs to be authenticated
curl --cookie "access_token=correct horse battery staple" http://localhost:3000/authenticated
#> Successfully authenticated!

# /auth2 needs to be authenticated too
curl --cookie "access_token=correct horse battery staple" http://localhost:3000/auth2
#> Successfully authenticated 2!
```
