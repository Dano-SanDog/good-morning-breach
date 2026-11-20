package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Dano-SanDog/good-morning-breach/internal/catalog"
	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
)

type handlerCatalogStore struct {
	catalog.Store
	deleteErr error
}

func (*handlerCatalogStore) ListCategories(context.Context) ([]catalog.Category, error) {
	return []catalog.Category{{ID: "other", Name: "Other", Enabled: true}}, nil
}
func (*handlerCatalogStore) CreateSource(_ context.Context, _ int64, s catalog.Source) (catalog.Source, error) {
	return s, nil
}
func (s *handlerCatalogStore) DeleteSource(context.Context, int64, string) error { return s.deleteErr }

func catalogRouter(t *testing.T, role string, store catalog.Store) http.Handler {
	t.Helper()
	service, err := identity.NewService(&sourceHealthIdentityStore{role: role}, make([]byte, 32), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	catalogService, err := catalog.NewService(store, service)
	if err != nil {
		t.Fatal(err)
	}
	router, err := newRouter(service, fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}}, catalogService)
	if err != nil {
		t.Fatal(err)
	}
	return router
}

func catalogRequest(method, path, body string, csrf, session bool) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if csrf {
		request.Header.Set("X-GMB-CSRF", "1")
		request.Header.Set("Content-Type", "application/json")
	}
	if session {
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "test-session"})
	}
	return request
}

const validSourceBody = `{"name":"Example Advisories","address":"https://example.com/feed.xml","format":"rss",
"licenseName":"CC BY 4.0","licenseUrl":"https://example.com/license","permittedUse":"Headline",
"attribution":"Example","contentPolicy":"headline_link","pollIntervalSeconds":3600,"enabled":true}`

func TestCatalogRoutesEnforceAuthentication(t *testing.T) {
	routes := []struct{ method, path, body string }{
		{http.MethodGet, "/api/admin/categories", ""},
		{http.MethodPost, "/api/admin/categories", `{"name":"X"}`},
		{http.MethodPatch, "/api/admin/categories/other", `{"enabled":false}`},
		{http.MethodDelete, "/api/admin/categories/other", `{}`},
		{http.MethodGet, "/api/admin/source-records", ""},
		{http.MethodPost, "/api/admin/sources", validSourceBody},
		{http.MethodPatch, "/api/admin/sources/x", `{"enabled":false}`},
		{http.MethodDelete, "/api/admin/sources/x", `{}`},
	}
	for _, tc := range []struct {
		role    string
		session bool
		want    int
	}{{"user", true, http.StatusForbidden}, {"admin", false, http.StatusUnauthorized}} {
		router := catalogRouter(t, tc.role, &handlerCatalogStore{})
		for _, r := range routes {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, catalogRequest(r.method, r.path, r.body, true, tc.session))
			if response.Code != tc.want {
				t.Errorf("%s %s as %s session=%v = %d; want %d", r.method, r.path, tc.role, tc.session, response.Code, tc.want)
			}
		}
	}
}

func TestCatalogMutationsRequireCSRF(t *testing.T) {
	router := catalogRouter(t, "admin", &handlerCatalogStore{})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, catalogRequest(http.MethodPost, "/api/admin/sources", validSourceBody, false, true))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestCatalogHandlersMapResults(t *testing.T) {
	router := catalogRouter(t, "admin", &handlerCatalogStore{deleteErr: catalog.ErrInUse})
	for _, tc := range []struct {
		name, method, path, body string
		want                     int
	}{
		{"list", http.MethodGet, "/api/admin/categories", "", http.StatusOK},
		{"create", http.MethodPost, "/api/admin/sources", validSourceBody, http.StatusCreated},
		{"unknown field", http.MethodPost, "/api/admin/sources", `{"name":"x","bogus":1}`, http.StatusBadRequest},
		{"http address", http.MethodPost, "/api/admin/sources", strings.Replace(validSourceBody, "https://example.com/feed.xml", "http://example.com/feed.xml", 1), http.StatusBadRequest},
		{"in use", http.MethodDelete, "/api/admin/sources/x", `{}`, http.StatusConflict},
		{"protected", http.MethodDelete, "/api/admin/categories/other", `{}`, http.StatusConflict},
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, catalogRequest(tc.method, tc.path, tc.body, true, true))
		if response.Code != tc.want {
			t.Errorf("%s = %d (%s); want %d", tc.name, response.Code, response.Body.String(), tc.want)
		}
	}
}
