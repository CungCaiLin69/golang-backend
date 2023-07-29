package controller

import (
	"database/sql"
	token "golang-backend/apps/pkg"
	"golang-backend/apps/response"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"
	"golang.org/x/crypto/bcrypt"
)

type AuthController struct {
	Db *sql.DB
}

type RegisterRequest struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password"`
	ImgUrl   string `json:"img_url"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required"`
	Password string `json:"password"`
}

type Auth struct {
	Id       int
	Email    string
	Password string
}

var (
	queryCreate = `
		INSERT INTO auth (email, password, img_url) 
		VALUES ($1, $2, $3)
	`

	queryFindByEmail = `
		SELECT id, email, password
		FROM auth
		WHERE email=$1
	`
)

func (a *AuthController) Register(ctx *gin.Context) {
	var req = RegisterRequest{}

	err := ctx.ShouldBindJSON(&req)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	val := validator.New()
	err = val.Struct(req)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	req.Password = string(hash)
	stmt, err := a.Db.Prepare(queryCreate)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	_, err = stmt.Exec(
		req.Email,
		req.Password,
		req.ImgUrl,
	)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	resp := response.ResponseAPI{
		StatusCode: http.StatusCreated,
		Message:    "Register Success",
	}
	ctx.JSON(resp.StatusCode, resp)
}

func (a *AuthController) Login(ctx *gin.Context) {
	var req = LoginRequest{}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})

		return
	}

	stmt, err := a.Db.Prepare(queryFindByEmail)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})

		return
	}

	row := stmt.QueryRow(req.Email)

	var auth = Auth{}

	err = row.Scan(
		&auth.Id,
		&auth.Email,
		&auth.Password,
	)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})

		return
	}

	bcrypt.CompareHashAndPassword([]byte(auth.Password), []byte(req.Password))
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})

		return
	}

	tok := token.PayloadToken{
		AuthId: auth.Id,
	}
	tokString, err := token.GenerateToken(&tok)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
	}

	resp := response.ResponseAPI{
		StatusCode: http.StatusOK,
		Message:    "Login Successfully",
		Payload:    gin.H{
			"token": tokString,
		},
	}
	ctx.JSON(resp.StatusCode, resp)
}

func (a *AuthController) Profile(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{
		"id": ctx.GetInt("authId"),
	})
}