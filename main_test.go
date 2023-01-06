// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package keyauth

import (
	"strings"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/utils"
)

func validateAPIKey(ctx *fiber.Ctx, s string) (bool, error) {
	if s == "" {
	  return false, &fiber.Error{Code: 403, Message: "Missing API key"}
	}
	if s == "valid-key" {
	  return true, nil
	}
	return false, &fiber.Error{Code: 403, Message: "Invalid API key"}
}

func TestKeyLookupHeader(t *testing.T) {
	// Initialize a Fiber app
	app := fiber.New()

	// Use the KeyAuth middleware with the default configuration
	app.Use(New())

	// Define a test handler
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("API key is valid")
	})

	// Test the default KeyLookup value "header:Authorization"
	// Create a request without an API key and  Send the request to the app
	res, err := app.Test(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ := ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusBadRequest)
    utils.AssertEqual(t, string(body), ErrMissingOrMalformedAPIKey.Error())

	// Create a request with a valid API key in the Authorization header
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer valid-key")

	// Send the request to the app
	res, err = app.Test(req)
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ = ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusOK)
    utils.AssertEqual(t, string(body), "API key is valid")
}

func TestKeyLookupParam(t *testing.T) {
    // Initialize a Fiber app with the KeyAuth middleware
    app := fiber.New()

	// define middleware
	authMiddleware := New(Config{
		KeyLookup:  "param:api_key",
		Validator:  func(c *fiber.Ctx, key string) (bool, error) {
		    if key == "valid-key" {
		        return true, nil
		    }
		    return false, ErrMissingOrMalformedAPIKey
		},
	})

    // Define a test handler
    app.Get("/:api_key", authMiddleware, func(c *fiber.Ctx) error {
        return c.SendString("API key is valid")
    })

    // Create a request without an API key and  Send the request to the app
    res, err := app.Test(httptest.NewRequest("GET", "/wrong-key", nil))
    if err != nil {
        t.Error(err)
    }

    // Read the response body into a string
    body, _ := ioutil.ReadAll(res.Body)

    // Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusBadRequest)
    utils.AssertEqual(t, string(body), ErrMissingOrMalformedAPIKey.Error())

    // Create a request with a valid API key in the "api_key" URL parameter
    res, err = app.Test(httptest.NewRequest("GET", "/valid-key", nil))
    if err != nil {
        t.Error(err)
    }

    // Read the response body into a string
    body, _ = ioutil.ReadAll(res.Body)

    // Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusOK)
    utils.AssertEqual(t, string(body), "API key is valid")
}

func TestKeyLookupQuery(t *testing.T) {
	// Initialize a Fiber app
	app := fiber.New()

	// Use the KeyAuth middleware with the "query:api_key" configuration
	app.Use(New(Config{
		KeyLookup: "query:api_key",
	}))

	// Define a test handler
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("API key is valid")
	})

	// Create a request without an API key and  Send the request to the app
	res, err := app.Test(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ := ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusBadRequest)
    utils.AssertEqual(t, string(body), ErrMissingOrMalformedAPIKey.Error())

	// Create a request with a valid API key in the "api_key" query parameter
	req := httptest.NewRequest("GET", "/?api_key=valid-key", nil)

	// Send the request to the app
	res, err = app.Test(req)
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ = ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusOK)
    utils.AssertEqual(t, string(body), "API key is valid")
}

func TestKeyLookupForm(t *testing.T) {
	// Initialize a Fiber app with the KeyAuth middleware
	// Use the KeyAuth middleware with the "form:api_key" configuration
	app := fiber.New()
	app.Use(New(Config{
		KeyLookup: "form:api_key",
	}))

	// Define a test handler
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("API key is valid")
	})

	// Create a request without an API key and  Send the request to the app
	res, err := app.Test(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ := ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusBadRequest)
    utils.AssertEqual(t, string(body), ErrMissingOrMalformedAPIKey.Error())

	// Create a request with a valid API key in the "api_key" form parameter
	req := httptest.NewRequest("GET", "/", strings.NewReader("api_key=valid-key"))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Send the request to the app
	res, err = app.Test(req)
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ = ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusOK)
    utils.AssertEqual(t, string(body), "API key is valid")
}

func TestKeyLookupCookie(t *testing.T) {
	// Initialize a Fiber app with the KeyAuth middleware
	// Use the KeyAuth middleware with the "cookie:api_key" configuration
	app := fiber.New()
	app.Use(New(Config{
		KeyLookup: "cookie:api_key",
	}))

	// Define a test handler
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("API key is valid")
	})

	// Create a request without an API key and  Send the request to the app
	res, err := app.Test(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ := ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusBadRequest)
    utils.AssertEqual(t, string(body), ErrMissingOrMalformedAPIKey.Error())

	// Create a request with a valid API key in the "api_key" cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "api_key",
		Value: "valid-key",
	})

	// Send the request to the app
	res, err = app.Test(req)
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ = ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusOK)
    utils.AssertEqual(t, string(body), "API key is valid")
}

func TestCustomSuccessAndFailureHandlers(t *testing.T) {
	// Initialize a Fiber app with the KeyAuth middleware
	// Use the KeyAuth middleware with the default configuration and custom SuccessHandler and ErrorHandler functions
	app := fiber.New()
	app.Use(New(Config{
		SuccessHandler: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusOK).SendString("API key is valid and request was handled by custom success handler")
		},
		ErrorHandler:func(c *fiber.Ctx, err error) error {
			return c.Status(fiber.StatusBadRequest).SendString("API key is invalid and request was handled by custom error handler")
		},
	}))

	// Define a test handler that should not be called
	app.Get("/", func(c *fiber.Ctx) error {
		t.Error("Test handler should not be called")
		return nil
	})

	// Create a request without an API key and send it to the app
	res, err := app.Test(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ := ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusBadRequest)
    utils.AssertEqual(t, string(body), "API key is invalid and request was handled by custom error handler")

	// Create a request with a valid API key in the Authorization header
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer valid-key")

	// Send the request to the app
	res, err = app.Test(req)
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ = ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusOK)
    utils.AssertEqual(t, string(body), "API key is valid and request was handled by custom success handler")
}

func TestCustomValidatorFunc(t *testing.T) {
	// Initialize a Fiber app with the KeyAuth middleware
	app := fiber.New()

	// Use the KeyAuth middleware with a custom Validator function
	app.Use(New(Config{
		Validator: validateAPIKey,
	}))

	// Define a test handler
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("API key is valid")
	})

	// Create a request with an invalid API key and send it to the app
	res, err := app.Test(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ := ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusBadRequest)
    utils.AssertEqual(t, string(body), ErrMissingOrMalformedAPIKey.Error())

	// Create a request with a valid API key and send it to the app
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer valid-key")
	res, err = app.Test(req)
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ = ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusOK)
    utils.AssertEqual(t, string(body), "API key is valid")
}

func TestCustomFilterFunc(t *testing.T) {
	// Initialize a Fiber app with the KeyAuth middleware
	// Use the KeyAuth middleware with a custom Filter function that only allows requests with the "/allowed" path
	app := fiber.New()

	app.Use(New(Config{
		Filter: func(c *fiber.Ctx) bool {
			return c.Path() == "/allowed"
		},
	}))

	// Define a test handler
	app.Get("/allowed", func(c *fiber.Ctx) error {
		return c.SendString("API key is valid and request was allowed by custom filter")
	})

	// Create a request with the "/allowed" path and send it to the app
	req := httptest.NewRequest("GET", "/allowed", nil)
	res, err := app.Test(req)
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ := ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusOK)
    utils.AssertEqual(t, string(body), "API key is valid and request was allowed by custom filter")

	// Create a request with a different path and send it to the app
	req = httptest.NewRequest("GET", "/not-allowed", nil)
	res, err = app.Test(req)
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ = ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusBadRequest)
    utils.AssertEqual(t, string(body), ErrMissingOrMalformedAPIKey.Error())
}

func TestAuthSchemeToken(t *testing.T) {
	// Initialize a Fiber app with the KeyAuth middleware
	// Use the KeyAuth middleware with the "AuthScheme: Token" configuration
	app := fiber.New()
	app.Use(New(Config{
		AuthScheme: "Token",
	}))

	// Define a test handler
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("API key is valid")
	})

	// Create a request with a valid API key in the "Token" Authorization header
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Token valid-key")

	// Send the request to the app
	res, err := app.Test(req)
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ := ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusOK)
    utils.AssertEqual(t, string(body), "API key is valid")
}

func TestAuthSchemeBasic(t *testing.T) {
	// Initialize a Fiber app with the KeyAuth middleware
	// Use the KeyAuth middleware with the "header:Authorization" and "Basic" configuration
	app := fiber.New()
	app.Use(New(Config{
		KeyLookup: "header:Authorization",
		AuthScheme: "Basic",
	}))

	// Define a test handler
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("API key is valid")
	})

	// Create a request without an API key and  Send the request to the app
	res, err := app.Test(httptest.NewRequest("GET", "/", nil))
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ := ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusBadRequest)
    utils.AssertEqual(t, string(body), ErrMissingOrMalformedAPIKey.Error())

	// Create a request with a valid API key in the "Authorization" header using the "Basic" scheme
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Basic dmFsaWQta2V5")

	// Send the request to the app
	res, err = app.Test(req)
	if err != nil {
		t.Error(err)
	}

	// Read the response body into a string
	body, _ = ioutil.ReadAll(res.Body)

	// Check that the response has the expected status code and body
	utils.AssertEqual(t, res.StatusCode, http.StatusOK)
    utils.AssertEqual(t, string(body), "API key is valid")
}
