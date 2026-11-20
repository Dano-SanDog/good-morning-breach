package httpserver

import (
	"errors"
	"net/http"

	"github.com/Dano-SanDog/good-morning-breach/internal/alerting"
	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
	"github.com/gin-gonic/gin"
)

type channelHandlers struct {
	identity *identity.Service
	contacts *alerting.ContactService
}

func registerChannelRoutes(router *gin.Engine, service *identity.Service, contacts *alerting.ContactService) {
	h := &channelHandlers{identity: service, contacts: contacts}
	router.GET("/api/alert-channels", h.view)
	router.PUT("/api/alert-channels", requireCSRF(), h.save)
	router.POST("/api/alert-channels/slack", requireCSRF(), h.saveSlack)
}

// account takes the account ID from the session only, never from the request
// (SC-064).
func (h *channelHandlers) account(c *gin.Context) (int64, bool) {
	token, _ := c.Cookie(sessionCookieName)
	user, err := h.identity.CurrentUser(c.Request.Context(), token)
	if err != nil {
		if errors.Is(err, identity.ErrSession) || errors.Is(err, identity.ErrNotFound) {
			logAuthorizationDenial(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required."})
		} else {
			writeInternalError(c, err)
		}
		return 0, false
	}
	return user.AccountID, true
}

func writeChannelError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, alerting.ErrInvalidInput):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid alert channel settings."})
	case errors.Is(err, alerting.ErrRateLimited):
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests. Try again later."})
	default:
		writeInternalError(c, err)
	}
}

func (h *channelHandlers) view(c *gin.Context) {
	id, ok := h.account(c)
	if !ok {
		return
	}
	view, err := h.contacts.View(c.Request.Context(), id)
	if err != nil {
		writeChannelError(c, err)
		return
	}
	c.JSON(http.StatusOK, view)
}

func (h *channelHandlers) save(c *gin.Context) {
	var request struct {
		Email *bool `json:"emailEnabled"`
		Slack *bool `json:"slackEnabled"`
	}
	if err := decodeStrictJSON(c, &request); err != nil || request.Email == nil || request.Slack == nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid alert channel settings."})
		return
	}
	id, ok := h.account(c)
	if !ok {
		return
	}
	if err := h.contacts.SaveChannels(c.Request.Context(), id, *request.Email, *request.Slack); err != nil {
		writeChannelError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *channelHandlers) saveSlack(c *gin.Context) {
	var request struct {
		Webhook *string `json:"webhook"`
	}
	if err := decodeStrictJSON(c, &request); err != nil || request.Webhook == nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid Slack webhook."})
		return
	}
	id, ok := h.account(c)
	if !ok {
		return
	}
	result, err := h.contacts.SaveSlackWebhook(c.Request.Context(), id, *request.Webhook)
	if errors.Is(err, alerting.ErrInvalidInput) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "That is not a Slack incoming webhook address."})
		return
	}
	if err != nil {
		writeChannelError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}
