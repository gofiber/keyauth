// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package keyauth

import (
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
)


func TestKeyAuth(t *testing.T) {

	// setup the fiber endpoint
	app := fiber.New()

	// use keyauth.New and keyauth.Config outside of testing
	app.Use(New(Config{
		KeyLookup:  "header:key",
		Validator:  func(c *fiber.Ctx, key string) (bool, error) {
			if key == c.Locals("token") {
				return true, nil
			}
			return false, ErrMissingOrMalformedAPIKey
		},
		ContextKey: "token",
		ApiKey:     "MySecretPassword",
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Successfully authenticated!")
	})

	// define test cases
	tests := []struct {
		description  string
		apiKey       string
		expectedCode int
		expectedBody string
	}{
		{
			description:  "Normal Authentication Case",
			apiKey:       "MySecretPassword",
			expectedCode: 200,
			expectedBody: "Successfully authenticated!",
		},
		{
			description:  "Wrong API Key",
			apiKey:       "WRONG KEY",
			expectedCode: 401,
			expectedBody: "missing or malformed API Key",
		},
		{
			description:  "Wrong API Key",
			apiKey:       "", // NO KEY
			expectedCode: 401,
			expectedBody: "missing or malformed API Key",
		},
	}

	// run the tests
	for _, test := range tests {
		var req *http.Request
		req, _ = http.NewRequest("GET", "/", nil)
		if test.apiKey != "" {
			req.Header.Set("key", test.apiKey)
		}

		res, err := app.Test(req, -1)

		utils.AssertEqual(t, nil, err, test.description)

		// test the body of the request
		body, err := ioutil.ReadAll(res.Body)
		utils.AssertEqual(t, test.expectedCode, res.StatusCode, test.description)

		// body
		utils.AssertEqual(t, nil, err, test.description)
		utils.AssertEqual(t, test.expectedBody, string(body), test.description)
	}
}


func TestMultipleKeyAuth(t *testing.T) {

	// setup the fiber endpoint
	app := fiber.New()

	// setup keyauth for /auth1
	app.Use(New(Config{
		Filter: func(c *fiber.Ctx) bool {
			return c.OriginalURL() != "/auth1"
		},
		KeyLookup: "header:key",
		Validator:  func(c *fiber.Ctx, key string) (bool, error) {
			if key == c.Locals("token_auth1") {
				return true, nil
			}
			return false, ErrMissingOrMalformedAPIKey
		},
		ContextKey: "token_auth1",
		ApiKey: "password1",
	}))

	// setup keyauth for /auth2
	app.Use(New(Config{
		Filter: func(c *fiber.Ctx) bool {
			return c.OriginalURL() != "/auth2"
		},
		KeyLookup: "header:key",
		Validator:  func(c *fiber.Ctx, key string) (bool, error) {
			if key == c.Locals("token_auth2") {
				return true, nil
			}
			return false, ErrMissingOrMalformedAPIKey
		},
		ContextKey: "token_auth2",
		ApiKey: "password2",
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("No auth needed!")
	})

	app.Get("/auth1", func(c *fiber.Ctx) error {
		return c.SendString("Successfully authenticated for auth1!")
	})

	app.Get("/auth2", func(c *fiber.Ctx) error {
		return c.SendString("Successfully authenticated for auth2!")
	})

	// define test cases
	tests := []struct {
		route 		 string
		description  string
		apiKey       string
		expectedCode int
		expectedBody string
	}{
		// No auth needed for /
		{
			route:        "/",
			description:  "No password needed",
			apiKey:       "",
			expectedCode: 200,
			expectedBody: "No auth needed!",
		},
		
		// auth needed for auth1
		{
			route:        "/auth1",
			description:  "Normal Authentication Case",
			apiKey:       "password1",
			expectedCode: 200,
			expectedBody: "Successfully authenticated for auth1!",
		},
		{
			route:        "/auth1",
			description:  "Wrong API Key",
			apiKey:       "WRONG KEY",
			expectedCode: 401,
			expectedBody: "missing or malformed API Key",
		},
		{
			route:        "/auth1",
			description:  "Wrong API Key",
			apiKey:       "", // NO KEY
			expectedCode: 401,
			expectedBody: "missing or malformed API Key",
		},

		// Auth 2 has a different password
		{
			route:        "/auth2",
			description:  "Normal Authentication Case for auth2",
			apiKey:       "password2",
			expectedCode: 200,
			expectedBody: "Successfully authenticated for auth2!",
		},
		{
			route:        "/auth2",
			description:  "Wrong API Key",
			apiKey:       "WRONG KEY",
			expectedCode: 401,
			expectedBody: "missing or malformed API Key",
		},
		{
			route:        "/auth2",
			description:  "Wrong API Key",
			apiKey:       "", // NO KEY
			expectedCode: 401,
			expectedBody: "missing or malformed API Key",
		},

	}

	// run the tests
	for _, test := range tests {
		var req *http.Request
		req, _ = http.NewRequest("GET", test.route, nil)
		if test.apiKey != "" {
			req.Header.Set("key", test.apiKey)
		}

		res, err := app.Test(req, -1)

		utils.AssertEqual(t, nil, err, test.description)

		// test the body of the request
		body, err := ioutil.ReadAll(res.Body)
		utils.AssertEqual(t, test.expectedCode, res.StatusCode, test.description)

		// body
		utils.AssertEqual(t, nil, err, test.description)
		utils.AssertEqual(t, test.expectedBody, string(body), test.description)
	}
}
