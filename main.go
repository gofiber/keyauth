// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber
package keyauth

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber"
)

// Config ...
type Config struct {
	// Filter defines a function to skip middleware.
	// Optional. Default: nil
	Filter func(*fiber.Ctx) bool

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "param:<name>"
	// - "form:<name>"
	// - "cookie:<name>"
	TokenLookup string

	// Validator defines a function you can pass
	// to check the token however you want
	// It will be called with the token
	// and is expected to return true or false to indicate
	// that the token is approved or not
	// Optional. Default: nil
	Validator func(string) bool

	// Context key to store the bearertoken from the token into context.
	// Optional. Default: "token".
	ContextKey string

	// AuthScheme to be used in the Authorization header.
	// Optional. Default: "Bearer".
	AuthScheme string

	// SuccessHandler defines a function which is executed for a valid token.
	// Optional. Default: c.Next()
	SuccessHandler func(*fiber.Ctx)

	// ErrorHandler defines a function which is executed for an invalid or missing token.
	// It may be used to define a custom error.
	// Optional. Default: 401 Unauthorized
	ErrorHandler func(*fiber.Ctx, error)
}

// New creates a middleware for use in Fiber.
func New(config ...Config) func(*fiber.Ctx) {
	// Init config
	var cfg Config
	if len(config) > 0 {
		cfg = config[0]
	}
	if cfg.TokenLookup == "" {
		cfg.TokenLookup = "header:" + fiber.HeaderAuthorization
	}
	if cfg.Validator == nil {
		cfg.Validator = func(t string) bool {
			return true
		}
	}
	if cfg.ContextKey == "" {
		cfg.ContextKey = "token"
	}
	if cfg.AuthScheme == "" && strings.ToLower(cfg.TokenLookup) == "header:authorization" {
		cfg.AuthScheme = "Bearer"
	}
	if cfg.SuccessHandler == nil {
		cfg.SuccessHandler = func(c *fiber.Ctx) {
			c.Next()
		}
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(c *fiber.Ctx, err error) {
			c.SendStatus(401)
		}
	}
	// Initialize
	parts := strings.Split(cfg.TokenLookup, ":")
	extractor := tokenFromHeader(parts[1], cfg.AuthScheme)
	switch parts[0] {
	case "query":
		extractor = tokenFromQuery(parts[1])
	case "param":
		extractor = tokenFromParam(parts[1])
	case "form":
		extractor = tokenFromForm(parts[1])
	case "cookie":
		extractor = tokenFromCookie(parts[1])
	}

	return func(c *fiber.Ctx) {
		// Filter request to skip middleware
		if cfg.Filter != nil && cfg.Filter(c) {
			c.Next()
			return
		}
		// Extract bearer token
		token, err := extractor(c)
		if !cfg.Validator(token) {
			cfg.ErrorHandler(c, err)
			return
		}
		c.Locals(cfg.ContextKey, token)
		cfg.SuccessHandler(c)
	}
}

// tokenFromHeader returns a function that extracts token from the request header.
func tokenFromHeader(header string, authScheme string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		auth := c.Get(header)
		l := len(authScheme)
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:], nil
		}
		return "", errors.New("Missing or malformed Bearer token")
	}
}

// tokenFromQuery returns a function that extracts token from the query string.
func tokenFromQuery(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		token := c.Query(param)
		if token == "" {
			return "", errors.New("Missing or malformed Bearer token")
		}
		return token, nil
	}
}

// tokenFromParam returns a function that extracts token from the url param string.
func tokenFromParam(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		token := c.Params(param)
		if token == "" {
			return "", errors.New("Missing or malformed Bearer token")
		}
		return token, nil
	}
}

// tokenFromParam returns a function that extracts token from the url param string.
func tokenFromForm(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		token := c.FormValue(param)
		if token == "" {
			return "", errors.New("Missing or malformed Bearer token")
		}
		return token, nil
	}
}

// tokenFromCookie returns a function that extracts token from the named cookie.
func tokenFromCookie(name string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		token := c.Cookies(name)
		if token == "" {
			return "", errors.New("Missing or malformed Bearer token")
		}
		return token, nil
	}
}
