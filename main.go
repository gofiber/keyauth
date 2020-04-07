// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber
// Special thanks to Echo: https://github.com/labstack/echo/blob/master/middleware/key_auth.go
package keyauth

import (
	"errors"
	"github.com/gofiber/fiber"
	"strings"
)

type Config struct {
	// Filter defines a function to skip middleware.
	// Optional. Default: nil
	Filter func(*fiber.Ctx) bool

	// SuccessHandler defines a function which is executed for a valid key.
	// Optional. Default: nil
	SuccessHandler func(*fiber.Ctx)

	// ErrorHandler defines a function which is executed for an invalid key.
	// It may be used to define a custom error.
	// Optional. Default: 401 Invalid or expired key
	ErrorHandler func(*fiber.Ctx, error)

	// KeyLookup is a string in the form of "<source>:<name>" that is used
	// to extract key from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "form:<name>"
	// - "param:<name>"
	// - "cookie:<name>"
	KeyLookup string

	// AuthScheme to be used in the Authorization header.
	// Optional. Default value "Bearer".
	AuthScheme string

	// Validator is a function to validate key.
	// Required.
	Validator func(string, *fiber.Ctx) (bool, error)

	keyExtractor func(*fiber.Ctx) (string, error)
}

// New ...
func New(config ...Config) func(*fiber.Ctx) {
	// Init config
	var cfg Config
	if len(config) > 0 {
		cfg = config[0]
	}
	if cfg.SuccessHandler == nil {
		cfg.SuccessHandler = func(c *fiber.Ctx) {
			c.Next()
		}
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(c *fiber.Ctx, err error) {
			if err.Error() == "Missing or malformed API Key" {
				c.Status(fiber.StatusBadRequest)
				c.SendString("Missing or malformed API Key")
			} else {
				c.Status(fiber.StatusUnauthorized)
				c.SendString("Invalid or expired API Key")
			}
		}
	}

	if cfg.KeyLookup == "" {
		cfg.KeyLookup = "header:" + fiber.HeaderAuthorization
	}
	if cfg.AuthScheme == "" {
		cfg.AuthScheme = "Bearer"
	}

	if cfg.Validator == nil {
		panic("fiber: key-auth middleware requires a validator function")
	}

	// Initialize
	parts := strings.Split(cfg.KeyLookup, ":")
	extractor := keyFromHeader(parts[1], cfg.AuthScheme)
	switch parts[0] {
	case "query":
		extractor = keyFromQuery(parts[1])
	case "form":
		extractor = keyFromForm(parts[1])
	case "param":
		extractor = keyFromParam(parts[1])
	case "cookie":
		extractor = keyFromCookie(parts[1])
	}

	// Return middleware handler
	return func(c *fiber.Ctx) {
		// Filter request to skip middleware
		if cfg.Filter != nil && cfg.Filter(c) {
			c.Next()
			return
		}

		// Extract and verify key
		key, err := extractor(c)
		if err != nil {
			cfg.ErrorHandler(c, err)
			return
		}

		valid, err := cfg.Validator(key, c)

		if err == nil && valid {
			cfg.SuccessHandler(c)
			return
		}
		cfg.ErrorHandler(c, err)
		return
	}
}

// keyFromHeader returns a function that extracts api key from the request header.
func keyFromHeader(header string, authScheme string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		auth := c.Get(header)
		l := len(authScheme)
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:], nil
		}
		return "", errors.New("Missing or malformed API Key")
	}
}

// keyFromQuery returns a function that extracts api key from the query string.
func keyFromQuery(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		key := c.Query(param)
		if key == "" {
			return "", errors.New("Missing or malformed API Key")
		}
		return key, nil
	}
}

// keyFromForm returns a `keyExtractor` that extracts api key from the form.
func keyFromForm(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		key := c.FormValue(param)
		if key == "" {
			return "", errors.New("Missing or malformed API Key")
		}
		return key, nil
	}
}

// keyFromParam returns a function that extracts api key from the url param string.
func keyFromParam(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		key := c.Params(param)
		if key == "" {
			return "", errors.New("Missing or malformed API Key")
		}
		return key, nil
	}
}

// keyFromCookie returns a function that extracts api key from the named cookie.
func keyFromCookie(name string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		key := c.Cookies(name)
		if key == "" {
			return "", errors.New("Missing or malformed API Key")
		}
		return key, nil
	}
}