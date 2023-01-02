// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package keyauth

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
)


func TestKeyAuth(t *testing.T) {

	// setup the fiber endpoint
	app := fiber.New()

	app.Use(New(Config{
		KeyLookup:  "header:key",
		Validator:  func(c *fiber.Ctx, key string) (bool, error) {
			if key == "MySecretPassword" {
				return true, nil
			}
			return false, ErrMissingOrMalformedAPIKey
		},
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Successfully authenticated!")
	})

	// define test cases
	tests := []struct {
		description  string
		APIKey       string
		expectedCode int
		expectedBody string
	}{
		{
			description:  "Normal Authentication Case",
			APIKey:       "MySecretPassword",
			expectedCode: 200,
			expectedBody: "Successfully authenticated!",
		},
		{
			description:  "Wrong API Key",
			APIKey:       "WRONG KEY",
			expectedCode: 401,
			expectedBody: "missing or malformed API Key",
		},
		{
			description:  "Wrong API Key",
			APIKey:       "", // NO KEY
			expectedCode: 401,
			expectedBody: "missing or malformed API Key",
		},
	}

	// run the tests
	for _, test := range tests {
		var req *http.Request
		req, _ = http.NewRequest("GET", "/", nil)
		if test.APIKey != "" {
			req.Header.Set("key", test.APIKey)
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

func TestAuthSources(t *testing.T) {

	var CorrectKey = "specials: !$%,.#\"!?~`<>@$^*(){}[]|/\\123"
	// define test cases
	testSources := []string {"header", "cookie", "query", "param", "form"}

	tests := []struct {
		route         string
		authTokenName string
		description   string
		APIKey        string
		expectedCode  int
		expectedBody  string
	}{
		{
			route:         "/",
			authTokenName: "access_token",
			description:   "auth with correct key",
			APIKey:        CorrectKey,
			expectedCode:  200,
			expectedBody:  "Success!",
		},
		{
			route:         "/",
			authTokenName: "access_token",
			description:   "auth with no key",
			APIKey:        "",
			expectedCode:  401, // 404 in case of param authentication
			expectedBody:  "missing or malformed API Key",
		},
		{
			route:         "/",
			authTokenName: "access_token",
			description:   "auth with wrong key",
			APIKey:        "WRONGKEY",
			expectedCode:  401,
			expectedBody:  "missing or malformed API Key",
		},
	}


	for _, authSource := range testSources {
		t.Run(authSource, func(t *testing.T) {
			for _, test := range tests {
				// setup the fiber endpoint
				// note that if UnescapePath: false (the default)
				// escaped characters (such as `\"`) will not be handled correctly in the tests
				app := fiber.New(fiber.Config{UnescapePath: true})

				authMiddleware := New(Config{
					KeyLookup:  authSource + ":" + test.authTokenName,
					Validator:  func(c *fiber.Ctx, key string) (bool, error) {
						if key == CorrectKey {
							return true, nil
						}
						return false, ErrMissingOrMalformedAPIKey
					},
				})

				var route string
				if authSource == "param" {
					route = test.route + ":" + test.authTokenName
					app.Use(route, authMiddleware)
				} else {
					route = test.route
					app.Use(authMiddleware)
				}

				app.Get(route, func(c *fiber.Ctx) error {
					return c.SendString("Success!")
				})

				// construct the test HTTP request
				var req *http.Request
				req, _ = http.NewRequest("GET", test.route, nil)
				
				// setup the apikey for the different auth schemes
				if authSource == "header" {

					req.Header.Set(test.authTokenName, test.APIKey)

				} else if authSource == "cookie" {

					req.Header.Set("Cookie", test.authTokenName + "=" + test.APIKey)

				} else if authSource == "query" || authSource == "form" {

					q := req.URL.Query()
					q.Add(test.authTokenName, test.APIKey)
					req.URL.RawQuery = q.Encode()

				} else if authSource == "param" {

					r := req.URL.Path
					r = r + url.PathEscape(test.APIKey)
					req.URL.Path = r

				}

				res, err := app.Test(req, -1)

				utils.AssertEqual(t, nil, err, test.description)

				// test the body of the request
				body, err := ioutil.ReadAll(res.Body)
				// for param authentication, the route would be /:access_token 
				// when the access_token is empty, it leads to a 404 (not found)
				// not a 401 (auth error)
				if authSource == "param" && test.APIKey == "" {
					test.expectedCode = 404
					test.expectedBody = "Cannot GET /"
				}
				utils.AssertEqual(t, test.expectedCode, res.StatusCode, test.description)

				// body
				utils.AssertEqual(t, nil, err, test.description)
				utils.AssertEqual(t, test.expectedBody, string(body), test.description)
			}
		})
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
			if key == "password1" {
				return true, nil
			}
			return false, ErrMissingOrMalformedAPIKey
		},
	}))

	// setup keyauth for /auth2
	app.Use(New(Config{
		Filter: func(c *fiber.Ctx) bool {
			return c.OriginalURL() != "/auth2"
		},
		KeyLookup: "header:key",
		Validator:  func(c *fiber.Ctx, key string) (bool, error) {
			if key == "password2" {
				return true, nil
			}
			return false, ErrMissingOrMalformedAPIKey
		},
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
		APIKey       string
		expectedCode int
		expectedBody string
	}{
		// No auth needed for /
		{
			route:        "/",
			description:  "No password needed",
			APIKey:       "",
			expectedCode: 200,
			expectedBody: "No auth needed!",
		},
		
		// auth needed for auth1
		{
			route:        "/auth1",
			description:  "Normal Authentication Case",
			APIKey:       "password1",
			expectedCode: 200,
			expectedBody: "Successfully authenticated for auth1!",
		},
		{
			route:        "/auth1",
			description:  "Wrong API Key",
			APIKey:       "WRONG KEY",
			expectedCode: 401,
			expectedBody: "missing or malformed API Key",
		},
		{
			route:        "/auth1",
			description:  "Wrong API Key",
			APIKey:       "", // NO KEY
			expectedCode: 401,
			expectedBody: "missing or malformed API Key",
		},

		// Auth 2 has a different password
		{
			route:        "/auth2",
			description:  "Normal Authentication Case for auth2",
			APIKey:       "password2",
			expectedCode: 200,
			expectedBody: "Successfully authenticated for auth2!",
		},
		{
			route:        "/auth2",
			description:  "Wrong API Key",
			APIKey:       "WRONG KEY",
			expectedCode: 401,
			expectedBody: "missing or malformed API Key",
		},
		{
			route:        "/auth2",
			description:  "Wrong API Key",
			APIKey:       "", // NO KEY
			expectedCode: 401,
			expectedBody: "missing or malformed API Key",
		},
	}

	// run the tests
	for _, test := range tests {
		var req *http.Request
		req, _ = http.NewRequest("GET", test.route, nil)
		if test.APIKey != "" {
			req.Header.Set("key", test.APIKey)
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
