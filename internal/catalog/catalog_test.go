package catalog

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Dano-SanDog/good-morning-breach/internal/identity"
)

type fakeAuth struct{ err error }

func (f fakeAuth) RequireAdmin(context.Context, string) (identity.AuthenticatedUser, error) {
	return identity.AuthenticatedUser{AccountID: 7, Role: "admin"}, f.err
}

type fakeStore struct {
	Store
	categories map[string]Category
	sources    map[string]Source
	created    []Source
}

func (f *fakeStore) GetCategory(_ context.Context, id string) (Category, error) {
	c, ok := f.categories[id]
	if !ok {
		return c, ErrNotFound
	}
	return c, nil
}
func (f *fakeStore) UpdateCategory(_ context.Context, _ int64, id, name string, enabled bool) error {
	f.categories[id] = Category{ID: id, Name: name, Enabled: enabled}
	return nil
}
func (f *fakeStore) DeleteCategory(context.Context, int64, string) error { return nil }
func (f *fakeStore) CreateCategory(_ context.Context, _ int64, id, name string) (Category, error) {
	return Category{ID: id, Name: name, Enabled: true}, nil
}
func (f *fakeStore) CreateSource(_ context.Context, _ int64, s Source) (Source, error) {
	f.created = append(f.created, s)
	return s, nil
}
func (f *fakeStore) GetSource(_ context.Context, id string) (Source, error) {
	s, ok := f.sources[id]
	if !ok {
		return s, ErrNotFound
	}
	return s, nil
}
func (f *fakeStore) UpdateSource(_ context.Context, _ int64, s Source) error {
	f.sources[s.ID] = s
	return nil
}

func validSource() Source {
	return Source{
		Name: "Example Advisories", Address: "https://example.com/feed.xml", Format: "rss",
		LicenseName: "CC BY 4.0", LicenseURL: "https://example.com/license", PermittedUse: "Headline and link",
		Attribution: "Example", ContentPolicy: "headline_link", PollIntervalSeconds: 3600, Enabled: true,
	}
}

func newTestService(t *testing.T, auth fakeAuth, store *fakeStore) *Service {
	t.Helper()
	s, err := NewService(store, auth)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAuthorizationHappensFirst(t *testing.T) {
	store := &fakeStore{}
	svc := newTestService(t, fakeAuth{err: identity.ErrAdminRequired}, store)
	ctx := context.Background()
	if _, err := svc.CreateSource(ctx, "t", validSource()); !errors.Is(err, identity.ErrAdminRequired) {
		t.Fatalf("CreateSource err = %v", err)
	}
	if err := svc.DeleteCategory(ctx, "t", "x"); !errors.Is(err, identity.ErrAdminRequired) {
		t.Fatalf("DeleteCategory err = %v", err)
	}
	if len(store.created) != 0 {
		t.Fatal("store was called")
	}
}

func TestCreateSourceValidation(t *testing.T) {
	cases := map[string]func(*Source){
		"http":                    func(s *Source) { s.Address = "http://example.com/feed" },
		"userinfo":                func(s *Source) { s.Address = "https://user:pw@example.com/feed" },
		"loopback ip":             func(s *Source) { s.Address = "https://127.0.0.1/feed" },
		"private ip":              func(s *Source) { s.Address = "https://[::ffff:10.0.0.1]/feed" },
		"localhost":               func(s *Source) { s.Address = "https://localhost/feed" },
		"internal host":           func(s *Source) { s.Address = "https://feeds.internal/feed" },
		"odd port":                func(s *Source) { s.Address = "https://example.com:8443/feed" },
		"fragment":                func(s *Source) { s.Address = "https://example.com/feed#x" },
		"license http":            func(s *Source) { s.LicenseURL = "http://example.com/l" },
		"no license":              func(s *Source) { s.LicenseName = " " },
		"bad format":              func(s *Source) { s.Format = "xml" },
		"bad policy":              func(s *Source) { s.ContentPolicy = "everything" },
		"fast poll":               func(s *Source) { s.PollIntervalSeconds = 60 },
		"control chars":           func(s *Source) { s.Name = "Bad\x00Name" },
		"empty slug":              func(s *Source) { s.Name = "!!!" },
		"reddit trailing dot":     func(s *Source) { s.Address = "https://www.reddit.com./r/netsec/.rss" },
		"cloudflare trailing dot": func(s *Source) { s.Address = "https://radar.cloudflare.com../x.rss" },
		"reddit":                  func(s *Source) { s.Address = "https://www.reddit.com/r/netsec/.rss" },
		"cloudflare":              func(s *Source) { s.Name = "Cloudflare Radar" },
		"abuse.ch":                func(s *Source) { s.Address = "https://urlhaus.abuse.ch/feeds/" },
		"acsc":                    func(s *Source) { s.Address = "https://www.cyber.gov.au/rss" },
		"vulnrichment":            func(s *Source) { s.Address = "https://github.com/cisagov/vulnrichment/commits.atom" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			store := &fakeStore{}
			svc := newTestService(t, fakeAuth{}, store)
			s := validSource()
			mutate(&s)
			_, err := svc.CreateSource(context.Background(), "t", s)
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("err = %v; want ValidationError", err)
			}
			if len(store.created) != 0 {
				t.Fatal("invalid source was stored")
			}
		})
	}
}

func TestCreateSourceGeneratesSlugID(t *testing.T) {
	store := &fakeStore{}
	svc := newTestService(t, fakeAuth{}, store)
	got, err := svc.CreateSource(context.Background(), "t", validSource())
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "example-advisories" {
		t.Fatalf("id = %q", got.ID)
	}
}

func TestUpdateSourceMergesAndRevalidates(t *testing.T) {
	existing := validSource()
	existing.ID = "example-advisories"
	store := &fakeStore{sources: map[string]Source{existing.ID: existing}}
	svc := newTestService(t, fakeAuth{}, store)
	bad := "http://example.com/x"
	if err := svc.UpdateSource(context.Background(), "t", existing.ID, SourcePatch{Address: &bad}); err == nil {
		t.Fatal("expected validation error")
	}
	off := false
	title := true
	if err := svc.UpdateSource(context.Background(), "t", existing.ID, SourcePatch{Enabled: &off, RequireCompleteTitle: &title}); err != nil {
		t.Fatal(err)
	}
	got := store.sources[existing.ID]
	if got.Enabled || !got.RequireCompleteTitle || got.Name != existing.Name {
		t.Fatalf("merged = %+v", got)
	}
	if err := svc.UpdateSource(context.Background(), "t", "missing", SourcePatch{Enabled: &off}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnablingWithoutLicenseRecordIsRejected(t *testing.T) {
	existing := validSource()
	existing.ID = "example-advisories"
	existing.Enabled = false
	store := &fakeStore{sources: map[string]Source{existing.ID: existing}}
	svc := newTestService(t, fakeAuth{}, store)
	empty, on := "", true
	if err := svc.UpdateSource(context.Background(), "t", existing.ID, SourcePatch{LicenseName: &empty, Enabled: &on}); err == nil {
		t.Fatal("expected error")
	}
}

func TestOtherCategoryIsProtected(t *testing.T) {
	store := &fakeStore{categories: map[string]Category{"other": {ID: "other", Name: "Other", Enabled: true}}}
	svc := newTestService(t, fakeAuth{}, store)
	off := false
	if err := svc.UpdateCategory(context.Background(), "t", "other", nil, &off); !errors.Is(err, ErrProtected) {
		t.Fatalf("disable err = %v", err)
	}
	if err := svc.DeleteCategory(context.Background(), "t", "other"); !errors.Is(err, ErrProtected) {
		t.Fatalf("delete err = %v", err)
	}
	name := "Misc"
	if err := svc.UpdateCategory(context.Background(), "t", "other", &name, nil); err != nil {
		t.Fatal(err)
	}
}

func TestCategoryNameValidation(t *testing.T) {
	svc := newTestService(t, fakeAuth{}, &fakeStore{})
	for _, name := range []string{"", "   ", "!!!", strings.Repeat("a", 81), "a\nb"} {
		if _, err := svc.CreateCategory(context.Background(), "t", name); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	got, err := svc.CreateCategory(context.Background(), "t", "  Zero Day Brokers ")
	if err != nil || got.ID != "zero-day-brokers" || got.Name != "Zero Day Brokers" {
		t.Fatalf("got %+v, %v", got, err)
	}
}
