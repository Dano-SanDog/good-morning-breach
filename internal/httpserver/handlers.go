package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"unicode/utf8"

	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
	"github.com/gin-gonic/gin"
)

const sessionCookieName = "__Host-gmb_session"
const credentialErrorMessage = "Email, password, or code is incorrect."

type apiHandlers struct {
	identity *identity.Service
}

func registerRoutes(router *gin.Engine, service *identity.Service, assets fs.FS) {
	api := &apiHandlers{identity: service}
	router.POST("/api/auth/login", requireCSRF(), api.login)
	router.GET("/api/auth/session", api.currentUser)
	router.GET("/api/auth/challenge", api.challenge)
	router.POST("/api/auth/activity", requireCSRF(), api.activity)
	router.POST("/api/auth/totp/setup/start", requireCSRF(), api.beginTOTPSetup)
	router.POST("/api/auth/totp/setup/confirm", requireCSRF(), api.confirmTOTPSetup)
	router.POST("/api/auth/totp/login", requireCSRF(), api.completeTOTPLogin)
	router.POST("/api/auth/logout", requireCSRF(), api.logout)
	router.GET("/api/stories", api.stories)

	fileServer := http.StripPrefix("/", http.FileServer(http.FS(assets)))
	router.GET("/", func(c *gin.Context) {
		fileServer.ServeHTTP(c.Writer, c.Request)
	})
	router.GET("/assets/*filepath", func(c *gin.Context) {
		fileServer.ServeHTTP(c.Writer, c.Request)
	})
}

func requireCSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
		if c.GetHeader("X-GMB-CSRF") != "1" || err != nil || mediaType != "application/json" {
			logAuthorizationDenial(c)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Request was rejected."})
			return
		}
		c.Next()
	}
}

func (h *apiHandlers) login(c *gin.Context) {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeStrictJSON(c, &request); err != nil ||
		len(request.Email) > 254 || !utf8.ValidString(request.Password) ||
		utf8.RuneCountInString(request.Password) > 256 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request."})
		return
	}

	previousToken, _ := c.Cookie(sessionCookieName)
	result, err := h.identity.PasswordLogin(c.Request.Context(), request.Email, request.Password, previousToken)
	if errors.Is(err, identity.ErrCredentials) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": credentialErrorMessage})
		return
	}
	if err != nil {
		writeInternalError(c, err)
		return
	}
	setSessionCookie(c, result.Token, 5*60)
	c.JSON(http.StatusOK, gin.H{"next": result.Next})
}

func (h *apiHandlers) currentUser(c *gin.Context) {
	token, _ := c.Cookie(sessionCookieName)
	user, err := h.identity.CurrentUser(c.Request.Context(), token)
	if errors.Is(err, identity.ErrSession) || errors.Is(err, identity.ErrNotFound) {
		logAuthorizationDenial(c)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required."})
		return
	}
	if err != nil {
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *apiHandlers) challenge(c *gin.Context) {
	token, _ := c.Cookie(sessionCookieName)
	challenge, err := h.identity.CurrentChallenge(c.Request.Context(), token)
	if errors.Is(err, identity.ErrSession) {
		logAuthorizationDenial(c)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required."})
		return
	}
	if err != nil {
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, challenge)
}

func (h *apiHandlers) activity(c *gin.Context) {
	var request struct{}
	if err := decodeStrictJSON(c, &request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request."})
		return
	}
	token, _ := c.Cookie(sessionCookieName)
	if err := h.identity.TouchSession(c.Request.Context(), token); err != nil {
		if errors.Is(err, identity.ErrSession) {
			logAuthorizationDenial(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required."})
			return
		}
		writeInternalError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *apiHandlers) beginTOTPSetup(c *gin.Context) {
	var request struct{}
	if err := decodeStrictJSON(c, &request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request."})
		return
	}
	token, _ := c.Cookie(sessionCookieName)
	secret, err := h.identity.BeginTOTPSetup(c.Request.Context(), token)
	if errors.Is(err, identity.ErrSession) || errors.Is(err, identity.ErrTOTPSetup) ||
		errors.Is(err, identity.ErrTOTPEnrolled) {
		logAuthorizationDenial(c)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required."})
		return
	}
	if err != nil {
		writeInternalError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"secret": secret})
}

func (h *apiHandlers) confirmTOTPSetup(c *gin.Context) {
	h.completeTOTP(c, true)
}

func (h *apiHandlers) completeTOTPLogin(c *gin.Context) {
	h.completeTOTP(c, false)
}

func (h *apiHandlers) completeTOTP(c *gin.Context, setup bool) {
	var request struct {
		Code string `json:"code"`
	}
	if err := decodeStrictJSON(c, &request); err != nil || !sixDigitCode(request.Code) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request."})
		return
	}
	token, _ := c.Cookie(sessionCookieName)
	user, newToken, err := h.identity.CompleteTOTP(c.Request.Context(), token, request.Code, setup)
	if errors.Is(err, identity.ErrCredentials) || errors.Is(err, identity.ErrSession) ||
		errors.Is(err, identity.ErrOTPReplay) || errors.Is(err, identity.ErrTOTPSetup) {
		if !errors.Is(err, identity.ErrCredentials) {
			logAuthorizationDenial(c)
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": credentialErrorMessage})
		return
	}
	if err != nil {
		writeInternalError(c, err)
		return
	}
	setSessionCookie(c, newToken, 8*60*60)
	c.JSON(http.StatusOK, user)
}

func (h *apiHandlers) logout(c *gin.Context) {
	var request struct{}
	if err := decodeStrictJSON(c, &request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request."})
		return
	}
	token, _ := c.Cookie(sessionCookieName)
	user, err := h.identity.CurrentUser(c.Request.Context(), token)
	if err != nil {
		if errors.Is(err, identity.ErrSession) {
			logAuthorizationDenial(c)
			clearSessionCookie(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required."})
			return
		}
		writeInternalError(c, err)
		return
	}
	if err := h.identity.Logout(c.Request.Context(), token); err != nil {
		writeInternalError(c, err)
		return
	}
	slog.Info("sign-out succeeded", "event", "logout", "account_id", user.AccountID, "outcome", "success")
	clearSessionCookie(c)
	c.Status(http.StatusNoContent)
}

func (h *apiHandlers) stories(c *gin.Context) {
	token, _ := c.Cookie(sessionCookieName)
	stories, err := h.identity.ListStories(c.Request.Context(), token)
	if errors.Is(err, identity.ErrSession) {
		logAuthorizationDenial(c)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required."})
		return
	}
	if err != nil {
		writeInternalError(c, err)
		return
	}
	if stories == nil {
		stories = []identity.Story{}
	}
	c.JSON(http.StatusOK, gin.H{"stories": stories})
}

func logAuthorizationDenial(c *gin.Context) {
	slog.Warn(
		"request denied",
		"event", "authorization_denial",
		"account_id", int64(0),
		"outcome", "denied",
		"correlation_id", requestCorrelationID(c),
	)
}

func decodeStrictJSON(c *gin.Context, destination any) error {
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func sixDigitCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, digit := range code {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func setSessionCookie(c *gin.Context, token string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func writeInternalError(c *gin.Context, err error) {
	requestID := requestCorrelationID(c)
	slog.Error("request failed", "correlation_id", requestID, "error", err)
	c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
		"error":         "An unexpected error occurred.",
		"correlationId": requestID,
	})
}
