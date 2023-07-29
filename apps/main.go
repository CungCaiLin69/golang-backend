package main

import (
	"golang-backend/apps/config"
	"golang-backend/apps/controller"
	token "golang-backend/apps/pkg"
	"golang-backend/apps/response"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func main() {
	db, err := config.ConnectDB()
	if err != nil{
		panic(err)
	}

	router := gin.Default()
	router.Use(CORS())

	authController := controller.AuthController{
		Db: db,
	}

	v1 := router.Group("/v1")

	router.GET("/ping", Ping)

	auth := v1.Group("auth")
	{
		auth.POST("register", authController.Register)
		auth.POST("login", authController.Login)
		auth.GET("profile", CheckAuth(), authController.Profile)
	}
	

	router.Run(":8080")
}

func CORS() gin.HandlerFunc{
	return func(ctx *gin.Context) {
		ctx.Header("Access-Control-Allow-Origin", "*")
		ctx.Header("Access-Control-Request-Methods", "GET, OPTIONS, POST, PUT, DELETE")
		ctx.Header("Access-Control-Request-Headers", "Authorization, Content-Type, Origin")
		ctx.Next()
	}
}

func Ping(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, map[string]interface{}{
		"message": "OK",
	})
}

func CheckAuth() gin.HandlerFunc{
	return func(ctx *gin.Context) {
		header := ctx.GetHeader("Authorization")

		bearerToken := strings.Split(header, "Bearer ")
		if len(bearerToken) != 2 {
			resp := response.ResponseAPI{
				StatusCode: http.StatusUnauthorized,
				Message: "Unauthorized",
			}
			ctx.AbortWithStatusJSON(resp.StatusCode, resp)
			return
		}
		payload, err := token.ValidateToken(bearerToken[1])
		if err != nil {
			resp := response.ResponseAPI {
				StatusCode: http.StatusUnauthorized,
				Message: "Invalid token",
				Payload: err.Error(),
			}
			ctx.AbortWithStatusJSON(resp.StatusCode, resp)
			return
		}
		ctx.Set("authId", payload.AuthId)

		ctx.Next()
	}
}