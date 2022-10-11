// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package keyauth

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
)

func Test_Default(t *testing.T) {
	app := fiber.New()

	app.Use(New(keyauth.Config{
		KeyLookup: "cookie:access_token",
		ContextKey: "my_token",
	}))
	  
	app.Get("/", func(c *fiber.Ctx) error {
		token, _ := c.Locals("my_token").(string)
		return c.SendString(token)
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/", ErrMissingOrMalformedAPIKey))
}