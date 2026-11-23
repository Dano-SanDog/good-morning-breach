package httpserver

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/Dano-SanDog/good-morning-breach/internal/catalog"
	"github.com/gin-gonic/gin"
)

type catalogHandlers struct {
	catalog *catalog.Service
}

type sourceRequest struct {
	Name                 *string `json:"name"`
	Address              *string `json:"address"`
	Format               *string `json:"format"`
	LicenseName          *string `json:"licenseName"`
	LicenseURL           *string `json:"licenseUrl"`
	PermittedUse         *string `json:"permittedUse"`
	Attribution          *string `json:"attribution"`
	ContentPolicy        *string `json:"contentPolicy"`
	RightsClass          *string `json:"rightsClass"`
	PollIntervalSeconds  *int64  `json:"pollIntervalSeconds"`
	Enabled              *bool   `json:"enabled"`
	RequireCompleteTitle *bool   `json:"requireCompleteTitle"`
}

func (r sourceRequest) patch() catalog.SourcePatch {
	return catalog.SourcePatch{
		Name: r.Name, Address: r.Address, Format: r.Format, LicenseName: r.LicenseName,
		LicenseURL: r.LicenseURL, PermittedUse: r.PermittedUse, Attribution: r.Attribution,
		ContentPolicy: r.ContentPolicy, RightsClass: r.RightsClass, PollIntervalSeconds: r.PollIntervalSeconds,
		Enabled: r.Enabled, RequireCompleteTitle: r.RequireCompleteTitle,
	}
}

func deref[T any](value *T) T {
	var zero T
	if value == nil {
		return zero
	}
	return *value
}

func registerCatalogRoutes(router *gin.Engine, service *catalog.Service) {
	h := &catalogHandlers{catalog: service}
	router.GET("/api/admin/categories", h.listCategories)
	router.POST("/api/admin/categories", requireCSRF(), h.createCategory)
	router.PATCH("/api/admin/categories/:id", requireCSRF(), h.updateCategory)
	router.DELETE("/api/admin/categories/:id", requireCSRF(), h.deleteCategory)
	router.GET("/api/admin/source-records", h.listSources)
	router.POST("/api/admin/sources", requireCSRF(), h.createSource)
	router.PATCH("/api/admin/sources/:id", requireCSRF(), h.updateSource)
	router.DELETE("/api/admin/sources/:id", requireCSRF(), h.deleteSource)
	router.GET("/api/admin/review-stories", h.listReviewStories)
	router.PUT("/api/admin/review-stories/:id", requireCSRF(), h.setExcerptApproval)
}

func (h *catalogHandlers) listReviewStories(c *gin.Context) {
	token, _ := c.Cookie(sessionCookieName)
	stories, err := h.catalog.ListReviewStories(c.Request.Context(), token)
	if err != nil {
		writeCatalogError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"stories": stories})
}

func (h *catalogHandlers) setExcerptApproval(c *gin.Context) {
	var request struct {
		Approved *bool `json:"approved"`
	}
	id, parseErr := strconv.ParseInt(c.Param("id"), 10, 64)
	if err := decodeStrictJSON(c, &request); err != nil || request.Approved == nil || parseErr != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request."})
		return
	}
	token, _ := c.Cookie(sessionCookieName)
	if err := h.catalog.SetExcerptApproval(c.Request.Context(), token, id, *request.Approved); err != nil {
		writeCatalogError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func writeCatalogError(c *gin.Context, err error) {
	var validation *catalog.ValidationError
	switch {
	case errors.As(err, &validation):
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": validation.Message})
	case errors.Is(err, catalog.ErrNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Record not found."})
	case errors.Is(err, catalog.ErrConflict),
		errors.Is(err, catalog.ErrInUse),
		errors.Is(err, catalog.ErrProtected):
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		if writeAdminError(c, err) {
			return
		}
		writeInternalError(c, err)
	}
}

func (h *catalogHandlers) listCategories(c *gin.Context) {
	token, _ := c.Cookie(sessionCookieName)
	categories, err := h.catalog.ListCategories(c.Request.Context(), token)
	if err != nil {
		writeCatalogError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"categories": categories})
}

func (h *catalogHandlers) createCategory(c *gin.Context) {
	var request struct {
		Name string `json:"name"`
	}
	if err := decodeStrictJSON(c, &request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request."})
		return
	}
	token, _ := c.Cookie(sessionCookieName)
	category, err := h.catalog.CreateCategory(c.Request.Context(), token, request.Name)
	if err != nil {
		writeCatalogError(c, err)
		return
	}
	c.JSON(http.StatusCreated, category)
}

func (h *catalogHandlers) updateCategory(c *gin.Context) {
	var request struct {
		Name    *string `json:"name"`
		Enabled *bool   `json:"enabled"`
	}
	if err := decodeStrictJSON(c, &request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request."})
		return
	}
	token, _ := c.Cookie(sessionCookieName)
	if err := h.catalog.UpdateCategory(c.Request.Context(), token, c.Param("id"), request.Name, request.Enabled); err != nil {
		writeCatalogError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *catalogHandlers) deleteCategory(c *gin.Context) {
	var request struct{}
	if err := decodeStrictJSON(c, &request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request."})
		return
	}
	token, _ := c.Cookie(sessionCookieName)
	if err := h.catalog.DeleteCategory(c.Request.Context(), token, c.Param("id")); err != nil {
		writeCatalogError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *catalogHandlers) listSources(c *gin.Context) {
	token, _ := c.Cookie(sessionCookieName)
	sources, err := h.catalog.ListSources(c.Request.Context(), token)
	if err != nil {
		writeCatalogError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"sources": sources})
}

func (h *catalogHandlers) createSource(c *gin.Context) {
	var request sourceRequest
	if err := decodeStrictJSON(c, &request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request."})
		return
	}
	token, _ := c.Cookie(sessionCookieName)
	source, err := h.catalog.CreateSource(c.Request.Context(), token, catalog.Source{
		Name: deref(request.Name), Address: deref(request.Address), Format: deref(request.Format),
		LicenseName: deref(request.LicenseName), LicenseURL: deref(request.LicenseURL),
		PermittedUse: deref(request.PermittedUse), Attribution: deref(request.Attribution),
		ContentPolicy: deref(request.ContentPolicy), RightsClass: deref(request.RightsClass), PollIntervalSeconds: deref(request.PollIntervalSeconds),
		Enabled: deref(request.Enabled), RequireCompleteTitle: deref(request.RequireCompleteTitle),
	})
	if err != nil {
		writeCatalogError(c, err)
		return
	}
	c.JSON(http.StatusCreated, source)
}

func (h *catalogHandlers) updateSource(c *gin.Context) {
	var request sourceRequest
	if err := decodeStrictJSON(c, &request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request."})
		return
	}
	token, _ := c.Cookie(sessionCookieName)
	if err := h.catalog.UpdateSource(c.Request.Context(), token, c.Param("id"), request.patch()); err != nil {
		writeCatalogError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *catalogHandlers) deleteSource(c *gin.Context) {
	var request struct{}
	if err := decodeStrictJSON(c, &request); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request."})
		return
	}
	token, _ := c.Cookie(sessionCookieName)
	if err := h.catalog.DeleteSource(c.Request.Context(), token, c.Param("id")); err != nil {
		writeCatalogError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
