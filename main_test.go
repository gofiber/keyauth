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

func validateAPIKey(c *fiber.Ctx, key string) (bool, error) {
	if key == c.Locals("ContextKey") {
		return true, nil
	}
	return false, ErrMissingOrMalformedAPIKey
}

func TestKeyAuth(t *testing.T) {

	// setup the fiber endpoint
	app := fiber.New()

	// use keyauth.New and keyauth.Config outside of testing
	app.Use(New(Config{
		KeyLookup:  "header:key",
		Validator:  validateAPIKey,
		ContextKey: "MySecretPassword",
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
