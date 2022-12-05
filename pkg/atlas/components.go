package atlas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/pg9182/ip2x"
	"github.com/r2northstar/atlas/pkg/api/api0"
	"github.com/r2northstar/atlas/pkg/cloudflare"
	"github.com/r2northstar/atlas/pkg/regionmap"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
)

var ErrRestartRequired = errors.New("restart required to apply updated config")

// TODO: finish implementing
type ServerNew struct {
	web            *webComponent
	ip2l           *ip2lComponent
	devIPMap       *devIPMapComponent
	hostFilter     *hostFilterComponent
	cloudflare     *cloudflareComponent
	regionMap      *regionMapComponent
	mainMenuPromos *mainMenuPromosComponent
}

// TODO: server main

// Configure (re)configures the server with c. If configuration fails, the
// server will be left in a valid state, but with a mix of the old and new
// configuration. If a restart is required to fully apply the configuration,
// [ErrRestartRequired] will be returned.
func (s *ServerNew) Configure(c *Config) error {
	ctx := context.Background()

	// TODO: configure logging, default to stdout

	var restart []component
	for _, m := range []component{
		s.web,
		s.ip2l,
		s.devIPMap,
		s.hostFilter,
		s.cloudflare,
		s.regionMap,
		s.mainMenuPromos,
	} {
		if err := m.Configure(ctx, c); err != nil {
			if !errors.Is(err, ErrRestartRequired) {
				return fmt.Errorf("configure %s: %w", m.Component(), err)
			}
			restart = append(restart, m)
		}
	}
	if len(restart) != 0 {
		var x []string
		for _, m := range restart {
			x = append(x, m.Component())
		}
		return fmt.Errorf("%w (components: %s)", ErrRestartRequired, x)
	}
	return nil
}

// component manages a single component of Atlas.
type component interface {
	// Component returns the component name.
	Component() string

	// Configure reloads (possibly returning [ErrRestartRequired]) or applies
	// the initial config. If an error is returned, the configuration should
	// left the way it was originally. Configure must be safe to be called while
	// the object is in use. Warnings and the current (but not errors) should be
	// written to the logger from [log.Ctx].
	Configure(context.Context, *Config) error
}

// webComponent serves redirects and static content.
type webComponent struct {
	h atomic.Pointer[http.HandlerFunc]
}

var (
	_ component = (*webComponent)(nil)
	_ component = (*ip2lComponent)(nil)
	_ component = (*devIPMapComponent)(nil)
	_ component = (*hostFilterComponent)(nil)
	_ component = (*cloudflareComponent)(nil)
	_ component = (*regionMapComponent)(nil)
	_ component = (*mainMenuPromosComponent)(nil)
)

func (m *webComponent) Component() string {
	return "Web"
}

// Configure reads redirects and configures the HTTP handler to serve files from
// c.Web.
func (m *webComponent) Configure(ctx context.Context, c *Config) error {
	if c.Web == "" {
		if m.h.Swap(nil) != nil {
			log.Ctx(ctx).Log().Msgf("disabled web handler")
		}
		return nil
	}

	web, err := filepath.Abs(c.Web)
	if err != nil {
		return err
	}

	var redirects map[string]string
	if buf, err := os.ReadFile(filepath.Join(web, "redirects.json")); err != nil {
		return fmt.Errorf("load redirects: %w", err)
	} else if err = json.Unmarshal(buf, &redirects); err != nil {
		return fmt.Errorf("load redirects: %w", err)
	}
	for r, u := range redirects {
		if t := strings.Trim(r, "/"); t != r {
			delete(redirects, r)
			redirects[u] = t
		}
	}

	static := http.FileServer(http.Dir(web))

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, ok := redirects[strings.Trim(r.URL.Path, "/")]; ok {
			http.Redirect(w, r, u, http.StatusTemporaryRedirect)
			return
		}
		static.ServeHTTP(w, r)
	})

	log.Ctx(ctx).Log().Msgf("serving static files from %q with %d redirects", web, len(redirects))
	m.h.Store(&h)
	return nil
}

func (m *webComponent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h := m.h.Load(); h != nil {
		h.ServeHTTP(w, r)
		return
	}
	http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
}

// ip2lComponent manages IP2Location databases.
type ip2lComponent struct {
	db atomic.Pointer[ip2x.DB]
}

func (m *ip2lComponent) Component() string {
	return "IP2Location"
}

// Configure opens the IP2Location database specified by c.IP2Location.
func (m *ip2lComponent) Configure(ctx context.Context, c *Config) error {
	if c.IP2Location == "" {
		if m.db.Swap(nil) != nil {
			log.Ctx(ctx).Log().Msgf("disabled ip2location database")
		}
		return nil
	}

	f, err := os.Open(c.IP2Location)
	if err != nil {
		return err
	}

	// note: we don't close the old file, instead depending on the Go runtime to
	// call close automatically during the finalizer when references to f go out
	// of scope, since this will keep the returned ip2x.DB and ip2x.Record
	// structs working while they are being used

	db, err := ip2x.New(f)
	if err != nil {
		f.Close()
		return err
	}

	if p, _ := db.Info(); p != ip2x.IP2Location {
		f.Close()
		return fmt.Errorf("not an ip2location database")
	}

	log.Ctx(ctx).Log().Msgf("loaded database %s", db)
	m.db.Store(db)
	return nil
}

func (m *ip2lComponent) Get() *ip2x.DB {
	if db := m.db.Load(); db != nil {
		return db
	}
	return nil
}

// devIPMapComponent provides middleware to remap request source IP addresses.
type devIPMapComponent struct {
	ms atomic.Pointer[[]devIPMapEntry]
}

type devIPMapEntry struct {
	Prefix netip.Prefix
	Addr   netip.Addr
}

func (m *devIPMapComponent) Component() string {
	return "DevIPMap"
}

// Configure parses IP mappings from c.DevMapIP.
func (m *devIPMapComponent) Configure(ctx context.Context, c *Config) error {
	if len(c.DevMapIP) == 0 {
		if m.ms.Swap(nil) != nil {
			log.Ctx(ctx).Log().Msgf("disabled dev ip map")
		}
		return nil
	}

	var ms []devIPMapEntry
	for _, m := range c.DevMapIP {
		a, b, ok := strings.Cut(m, "=")
		if !ok {
			return fmt.Errorf("parse ip mapping %q: missing equals sign", m)
		}

		addr, err := netip.ParseAddr(b)
		if err != nil {
			return fmt.Errorf("parse ip mapping %q: invalid address: %w", m, err)
		}
		if strings.ContainsRune(a, '/') {
			if pfx, err := netip.ParsePrefix(a); err == nil {
				ms = append(ms, devIPMapEntry{pfx, addr})
			} else {
				return fmt.Errorf("parse ip mapping %q: invalid prefix: %w", m, err)
			}
		}

		x, err := netip.ParseAddr(a)
		if err != nil {
			return fmt.Errorf("parse ip mapping %q: invalid prefix: %w", m, err)
		}

		pfx, err := x.Prefix(x.BitLen())
		if err != nil {
			panic(err)
		}
		ms = append(ms, devIPMapEntry{pfx, addr})
	}

	log.Ctx(ctx).Log().Msgf("mapping %d ip prefixes", len(ms))
	m.ms.Store(&ms)
	return nil
}

func (m *devIPMapComponent) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ms := m.ms.Load(); ms != nil {
			if x, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
				for _, m := range *ms {
					if m.Prefix.Contains(x.Addr()) {
						r2 := *r
						r2.RemoteAddr = netip.AddrPortFrom(m.Addr, x.Port()).String()
						r = &r2
					}
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// hostFilterComponent blocks requests from unknown hostnames.
type hostFilterComponent struct {
	hs atomic.Pointer[map[string]struct{}]
}

func (m *hostFilterComponent) Component() string {
	return "HostFilter"
}

// Configure parses hostnames from c.Host.
func (m *hostFilterComponent) Configure(ctx context.Context, c *Config) error {
	if len(c.Host) == 0 {
		if m.hs.Swap(nil) != nil {
			log.Ctx(ctx).Log().Msgf("disabled host filter")
		}
		return nil
	}

	hs := map[string]struct{}{}
	for _, n := range c.Host {
		hs[strings.ToLower(n)] = struct{}{}
	}

	log.Ctx(ctx).Log().Msgf("filtering %d hosts", len(hs))
	m.hs.Store(&hs)
	return nil
}

func (m *hostFilterComponent) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hs := m.hs.Load(); hs != nil {
			x := []byte(r.Host)
			for i := len(x) - 1; i >= 0; i-- {
				xc := x[i]
				if xc < '0' || xc > '9' {
					if xc == ':' {
						x = x[:i]
					}
					break
				}
			}
			if _, ok := (*hs)[strings.ToLower(string(x))]; ok {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Cache-Control", "private, no-cache, no-store")
			w.Header().Set("Expires", "0")
			w.Header().Set("Pragma", "no-cache")
			http.Error(w, "Go away.", http.StatusForbidden)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

// cloudflareComponent adds real request IPs from Cloudflare headers.
type cloudflareComponent struct {
	enabled atomic.Bool
}

func (m *cloudflareComponent) Component() string {
	return "Cloudflare"
}

// Configure enables or disables the middleware based on c.Cloudflare.
func (m *cloudflareComponent) Configure(ctx context.Context, c *Config) error {
	if !c.Cloudflare {
		if m.enabled.Swap(false) {
			log.Ctx(ctx).Log().Msgf("disabled cloudflare middleware")
		}
		return nil
	}

	log.Ctx(ctx).Log().Msgf("enabled cloudflare middleware")
	m.enabled.Store(true)
	return nil
}

func (m *cloudflareComponent) Middleware(next http.Handler) http.Handler {
	return cloudflare.RealIP(func(r *http.Request, err error) {
		hlog.FromRequest(r).
			Warn().
			Err(err).
			Str("request_ip", r.RemoteAddr).
			Msg("failed to use cloudflare ip")
	})(next)
}

// regionMapComponent maps IP information to region names.
type regionMapComponent struct {
	lookup atomic.Pointer[func(netip.Addr, ip2x.Record) (string, error)]
}

func (m *regionMapComponent) Component() string {
	return "RegionMap"
}

// Configure configures the region map from c.API0_RegionMap.
func (m *regionMapComponent) Configure(ctx context.Context, c *Config) error {
	switch v := c.API0_RegionMap; v {
	case "", "none":
		if m.lookup.Swap(nil) != nil {
			log.Ctx(ctx).Log().Msgf("disabled region map")
		}
		return nil
	case "default":
		fn := regionmap.GetRegion
		log.Ctx(ctx).Log().Msgf("using default region map")
		m.lookup.Store(&fn)
		return nil
	default:
		return fmt.Errorf("unknown region map type %q", v)
	}
}

func (m *regionMapComponent) Get() func(netip.Addr, ip2x.Record) (string, error) {
	if fn := m.lookup.Load(); fn != nil {
		return *fn
	}
	return nil
}

// mainMenuPromosComponent gets main menu promos.
type mainMenuPromosComponent struct {
	mmp atomic.Pointer[func(*http.Request) api0.MainMenuPromos]
}

func (m *mainMenuPromosComponent) Component() string {
	return "MainMenuPromos"
}

// Configure loads the main menu promos from c.API0_MainMenuPromos.
func (m *mainMenuPromosComponent) Configure(ctx context.Context, c *Config) error {
	switch typ, arg, _ := strings.Cut(c.API0_MainMenuPromos, ":"); typ {
	case "none":
		if m.mmp.Swap(nil) != nil {
			log.Ctx(ctx).Log().Msgf("main menu promos disabled")
		}
		return nil
	case "file":
		p, err := filepath.Abs(arg)
		if err != nil {
			return fmt.Errorf("file: resolve %q: %w", arg, err)
		}
		fn := func(*http.Request) api0.MainMenuPromos {
			var mmp api0.MainMenuPromos
			if buf, err1 := os.ReadFile(p); err1 != nil {
				err = err1
			} else if err = json.Unmarshal(buf, &mmp); err != nil {
				err = err1
			}
			return mmp
		}
		if fn(nil); err != nil {
			log.Ctx(ctx).Warn().Err(err).Msgf("failed to read maino menu promos form file %q", p)
		}
		log.Ctx(ctx).Log().Msgf("using main menu promos from file %q", p)
		m.mmp.Swap(&fn)
		return nil
	default:
		return fmt.Errorf("unknown source %q", typ)
	}
}

func (m *mainMenuPromosComponent) ForRequest(r *http.Request) api0.MainMenuPromos {
	if fn := m.mmp.Load(); fn != nil {
		return (*fn)(r)
	}
	return api0.MainMenuPromos{}
}

// TODO: no components, but track changes (and force restart) for: origin, storage, tls, addr, api0
