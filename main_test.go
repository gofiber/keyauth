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
	tests := []struct {
		route 		  string
		authSource    string
		authTokenName string
		description   string
		APIKey        string
		expectedCode  int
		expectedBody  string
	}{
		// header:access_token auth
		{
			route:         "/",
			authSource:    "header",
			authTokenName: "access_token",
			description:   "Testing Header:access_token",
			APIKey:        CorrectKey,
			expectedCode:  200,
			expectedBody:  "Success!",
		},
		{
			route:         "/",
			authSource:    "header",
			authTokenName: "access_token",
			description:   "Testing Header:access_token with a wrong key",
			APIKey:        "WRONGKEY",
			expectedCode:  401,
			expectedBody:  "missing or malformed API Key",
		},

		// cookie:access_token auth
		{
			route:         "/",
			authSource:    "cookie",
			authTokenName: "access_token",
			description:   "Testing cookie:access_token",
			APIKey:        CorrectKey,
			expectedCode:  200,
			expectedBody:  "Success!",
		},
		{
			route:         "/",
			authSource:    "cookie",
			authTokenName: "access_token",
			description:   "Testing cookie:access_token with a wrong key",
			APIKey:        "WRONGKEY",
			expectedCode:  401,
			expectedBody:  "missing or malformed API Key",
		},
		
		// query:access_token auth
		{
			route:         "/",
			authSource:    "query",
			authTokenName: "access_token",
			description:   "Testing query:access_token",
			APIKey:        CorrectKey,
			expectedCode:  200,
			expectedBody:  "Success!",
		},
		{
			route:         "/",
			authSource:    "query",
			authTokenName: "access_token",
			description:   "Testing query:access_token with a wrong key",
			APIKey:        "WRONGKEY",
			expectedCode:  401,
			expectedBody:  "missing or malformed API Key",
		},

		// param:access_token auth
		{
			route:         "/key/", // will end as '/key/:access_token'
			authSource:    "param",
			authTokenName: "access_token",
			description:   "Testing param:access_token",
			APIKey:        CorrectKey,
			expectedCode:  200,
			expectedBody:  "Success!",
		},
		{
			route:         "/key/",
			authSource:    "param",
			authTokenName: "access_token",
			description:   "Testing param:access_token with a wrong key",
			APIKey:        "WRONGKEY",
			expectedCode:  401,
			expectedBody:  "missing or malformed API Key",
		},
		
		// form:access_token auth
		{
			route:         "/",
			authSource:    "form",
			authTokenName: "access_token",
			description:   "Testing form:access_token",
			APIKey:        CorrectKey,
			expectedCode:  200,
			expectedBody:  "Success!",
		},
		{
			route:         "/",
			authSource:    "form",
			authTokenName: "access_token",
			description:   "Testing form:access_token with a wrong key",
			APIKey:        "WRONGKEY",
			expectedCode:  401,
			expectedBody:  "missing or malformed API Key",
		},
	}


	for _, test := range tests {
		// setup the fiber endpoint
		// note that if UnescapePath: false (the default)
		// escaped characters (such as `\"`) will not be handled correctly in the tests
		app := fiber.New(fiber.Config{UnescapePath: true})
		authMiddleware := New(Config{
			KeyLookup:  test.authSource + ":" + test.authTokenName,
			Validator:  func(c *fiber.Ctx, key string) (bool, error) {
				if key == CorrectKey {
					return true, nil
				}
				return false, ErrMissingOrMalformedAPIKey
			},
		})

		var route string
		if test.authSource == "param" {
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
		if test.authSource == "header" {

			req.Header.Set(test.authTokenName, test.APIKey)

		} else if test.authSource == "cookie" {
			
			req.Header.Set("Cookie", test.authTokenName + "=" + test.APIKey)

		} else if test.authSource == "query" || test.authSource == "form" {
			
			q := req.URL.Query()
			q.Add(test.authTokenName, test.APIKey)
			req.URL.RawQuery = q.Encode()

		} else if test.authSource == "param" {
			
			r := req.URL.Path
			r = r + url.PathEscape(test.APIKey)
			req.URL.Path = r

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
