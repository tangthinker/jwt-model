package middleware

import (
	"github.com/gofiber/fiber/v3"
	"github.com/tangthinker/jwt-model/core"
)

func FiberCheckLogin(author core.Author) fiber.Handler {

	return func(ctx fiber.Ctx) error {

		headerMap := ctx.GetReqHeaders()

		authHead := headerMap["Authorization"]

		if authHead == nil || len(authHead) == 0 {
			return ctx.Status(401).SendString("Unauthorized")
		}

		token := authHead[0]

		if token == "" {
			return ctx.Status(401).SendString("Unauthorized")
		}

		userId, extra, err := author.Verify(token)
		if err != nil {
			return ctx.Status(401).SendString("Unauthorized")
		}

		ctx.Set(CtxUserIdKey, userId)
		ctx.Set(CtxExtraInfoKey, extra)

		return ctx.Next()

	}

}
