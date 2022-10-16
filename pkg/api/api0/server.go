package api0

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/pg9182/atlas/pkg/a2s"
	"github.com/pg9182/atlas/pkg/api/api0/api0gameserver"
	"github.com/rs/zerolog/hlog"
)

func (h *Handler) handleServerUpsert(w http.ResponseWriter, r *http.Request) {
	// note: if the API is confusing, see:
	//  - https://github.com/R2Northstar/NorthstarLauncher/commit/753dda6231bbb2adf585bbc916c0b220e816fcdc
	//  - https://github.com/R2Northstar/NorthstarLauncher/blob/v1.9.7/NorthstarDLL/masterserver.cpp

	var isCreate, canCreate, isUpdate, canUpdate bool
	switch r.URL.Path {
	case "/server/add_server":
		isCreate = true
		canCreate = true
	case "/server/update_values":
		canCreate = true
		fallthrough
	case "/server/heartbeat":
		isUpdate = true
		canUpdate = true
	default:
		panic("unhandled path")
	}

	if r.Method != http.MethodOptions && r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Cache-Control", "private, no-cache, no-store")
	w.Header().Set("Expires", "0")
	w.Header().Set("Pragma", "no-cache")

	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "OPTIONS, POST")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if !h.checkLauncherVersion(r) {
		respFail(w, r, http.StatusBadRequest, ErrorCode_UNSUPPORTED_VERSION.MessageObj())
		return
	}

	raddr, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		hlog.FromRequest(r).Error().
			Err(err).
			Msgf("failed to parse remote ip %q", r.RemoteAddr)
		respFail(w, r, http.StatusInternalServerError, ErrorCode_INTERNAL_SERVER_ERROR.MessageObj())
		return
	}

	if !h.AllowGameServerIPv6 {
		if raddr.Addr().Is6() {
			respFail(w, r, http.StatusBadRequest, ErrorCode_BAD_REQUEST.MessageObjf("ipv6 is not currently supported (ip %s)", raddr.Addr()))
			return
		}
	}

	var l ServerListLimit
	if n := h.MaxServers; n > 0 {
		l.MaxServers = n
	} else if n == 0 {
		l.MaxServers = 1000
	}
	if n := h.MaxServersPerIP; n > 0 {
		l.MaxServersPerIP = n
	} else if n == 0 {
		l.MaxServersPerIP = 50
	}

	var s *Server
	if canCreate {
		s = &Server{}
	}

	var u *ServerUpdate
	if canUpdate {
		u = &ServerUpdate{
			Heartbeat: true,
			ExpectIP:  raddr.Addr(),
		}
	}

	if canUpdate {
		if v := r.URL.Query().Get("id"); v == "" {
			if isUpdate {
				respFail(w, r, http.StatusBadRequest, ErrorCode_BAD_REQUEST.MessageObjf("port param is required"))
				return
			}
		} else {
			u.ID = v
		}
	}

	if canCreate {
		if v := r.URL.Query().Get("port"); v == "" {
			if isCreate {
				respFail(w, r, http.StatusBadRequest, ErrorCode_BAD_REQUEST.MessageObjf("port param is required"))
				return
			}
		} else if n, err := strconv.ParseUint(v, 10, 16); err != nil {
			respFail(w, r, http.StatusBadRequest, ErrorCode_BAD_REQUEST.MessageObjf("port param is invalid: %v", err))
			return
		} else {
			s.Addr = netip.AddrPortFrom(raddr.Addr(), uint16(n))
		}

		if v := r.URL.Query().Get("authPort"); v == "" {
			if isCreate {
				respFail(w, r, http.StatusBadRequest, ErrorCode_BAD_REQUEST.MessageObjf("authPort param is required"))
				return
			}
		} else if n, err := strconv.ParseUint(v, 10, 16); err != nil {
			respFail(w, r, http.StatusBadRequest, ErrorCode_BAD_REQUEST.MessageObjf("authPort param is invalid: %v", err))
			return
		} else {
			s.AuthPort = uint16(n)
		}

		if v := r.URL.Query().Get("password"); len(v) > 128 {
			if isCreate {
				respFail(w, r, http.StatusBadRequest, ErrorCode_BAD_REQUEST.MessageObjf("password is too long"))
				return
			}
		} else {
			s.Password = v
		}
	}

	if canCreate || canUpdate {
		if v := r.URL.Query().Get("name"); v == "" {
			if isCreate {
				respFail(w, r, http.StatusBadRequest, ErrorCode_BAD_REQUEST.MessageObjf("name param must not be empty"))
				return
			}
		} else {
			if h.CleanBadWords != nil {
				v = h.CleanBadWords(v)
			}
			if n := 256; len(v) > n { // NorthstarLauncher@v1.9.7 limits it to 63
				v = v[:n]
			}
			if canCreate {
				s.Name = v
			}
			if canUpdate {
				u.Name = &v
			}
		}

		if v := r.URL.Query().Get("description"); v != "" {
			if h.CleanBadWords != nil {
				v = h.CleanBadWords(v)
			}
			if n := 1024; len(v) > n { // NorthstarLauncher@v1.9.7 doesn't have a limit
				v = v[:n]
			}
			if canCreate {
				s.Description = v
			}
			if canUpdate {
				u.Description = &v
			}
		}

		if v := r.URL.Query().Get("map"); v != "" {
			if n := 64; len(v) > n { // NorthstarLauncher@v1.9.7 limits it to 31
				v = v[:n]
			}
			if canCreate {
				s.Map = v
			}
			if canUpdate {
				u.Map = &v
			}
		}

		if v := r.URL.Query().Get("playlist"); v != "" {
			if n := 64; len(v) > n { // NorthstarLauncher@v1.9.7 limits it to 15
				v = v[:n]
			}
			if canCreate {
				s.Playlist = v
			}
			if canUpdate {
				u.Playlist = &v
			}
		}

		if n, err := strconv.ParseUint(r.URL.Query().Get("playerCount"), 10, 8); err == nil {
			if canCreate {
				s.PlayerCount = int(n)
			}
			if canUpdate {
				x := int(n)
				u.PlayerCount = &x
			}
		}

		if n, err := strconv.ParseUint(r.URL.Query().Get("maxPlayers"), 10, 8); err == nil {
			if canCreate {
				s.MaxPlayers = int(n)
			}
			if canUpdate {
				x := int(n)
				u.MaxPlayers = &x
			}
		}
	}

	if canCreate {
		var modInfoErr error
		if err := r.ParseMultipartForm(1 << 18 /*.25 MB*/); err == nil {
			if mf, mfHdr, err := r.FormFile("modinfo"); err == nil {
				if mfHdr.Size < 1<<18 {
					var obj struct {
						Mods []struct {
							Name             string `json:"Name"`
							Version          string `json:"Version"`
							RequiredOnClient bool   `json:"RequiredOnClient"`
						} `json:"Mods"`
					}
					if err := json.NewDecoder(mf).Decode(&obj); err == nil {
						for _, m := range obj.Mods {
							if m.Name != "" {
								if m.Version == "" {
									m.Version = "0.0.0"
								}
								s.ModInfo = append(s.ModInfo, ServerModInfo{
									Name:             m.Name,
									Version:          m.Version,
									RequiredOnClient: m.RequiredOnClient,
								})
							}
						}
					} else {
						modInfoErr = fmt.Errorf("parse modinfo file: %w", err)
					}
				} else {
					modInfoErr = fmt.Errorf("get modinfo file: too large (size %d)", mfHdr.Size)
				}
				mf.Close()
			} else {
				modInfoErr = fmt.Errorf("get modinfo file: %w", err)
			}
		} else {
			if isCreate {
				modInfoErr = fmt.Errorf("parse multipart form: %w", err)
			}
		}
		if modInfoErr != nil {
			hlog.FromRequest(r).Warn().
				Err(err).
				Msgf("failed to parse modinfo")
		}
	}

	nsrv, err := h.ServerList.ServerHybridUpdatePut(u, s, l)
	if err != nil {
		if errors.Is(err, ErrServerListUpdateWrongIP) {
			respFail(w, r, http.StatusForbidden, ErrorCode_UNAUTHORIZED_GAMESERVER.MessageObjf("%v", err))
			return
		}
		if errors.Is(err, ErrServerListUpdateServerDead) {
			respFail(w, r, http.StatusForbidden, ErrorCode_UNAUTHORIZED_GAMESERVER.MessageObjf("no such server"))
			return
		}
		if errors.Is(err, ErrServerListDuplicateAuthAddr) {
			respFail(w, r, http.StatusForbidden, ErrorCode_DUPLICATE_SERVER.MessageObjf("%v", err))
			return
		}
		if errors.Is(err, ErrServerListLimitExceeded) {
			respFail(w, r, http.StatusInternalServerError, ErrorCode_INTERNAL_SERVER_ERROR.MessageObjf("%v", err))
			return
		}
		hlog.FromRequest(r).Error().
			Err(err).
			Msgf("failed to update server list")
		respFail(w, r, http.StatusInternalServerError, ErrorCode_INTERNAL_SERVER_ERROR.MessageObj())
		return
	}

	if !nsrv.VerificationDeadline.IsZero() {
		ctx, cancel := context.WithDeadline(r.Context(), nsrv.VerificationDeadline)
		defer cancel()

		if err := api0gameserver.Verify(ctx, s.AuthAddr()); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				err = fmt.Errorf("request timed out")
			}
			var code ErrorCode
			if errors.Is(err, api0gameserver.ErrInvalidResponse) {
				code = ErrorCode_BAD_GAMESERVER_RESPONSE
			} else {
				code = ErrorCode_NO_GAMESERVER_RESPONSE
			}
			respFail(w, r, http.StatusBadGateway, code.MessageObjf("failed to connect to auth port: %v", err))
			return
		}

		if err := a2s.Probe(s.Addr, time.Until(nsrv.VerificationDeadline)); err != nil {
			respFail(w, r, http.StatusBadGateway, ErrorCode_BAD_GAMESERVER_RESPONSE.MessageObjf("failed to connect to game port: %v", err))
			return
		}

		if !h.ServerList.VerifyServer(nsrv.ID) {
			respFail(w, r, http.StatusBadGateway, ErrorCode_NO_GAMESERVER_RESPONSE.MessageObjf("verification timed out"))
			return
		}
	}

	respJSON(w, r, http.StatusOK, map[string]any{
		"success":         true,
		"id":              nsrv.ID,
		"serverAuthToken": nsrv.ServerAuthToken,
	})
}

func (h *Handler) handleServerRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodOptions && r.Method != http.MethodDelete {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Cache-Control", "private, no-cache, no-store")
	w.Header().Set("Expires", "0")
	w.Header().Set("Pragma", "no-cache")

	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", "OPTIONS, DELETE")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	raddr, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		hlog.FromRequest(r).Error().
			Err(err).
			Msgf("failed to parse remote ip %q", r.RemoteAddr)
		respFail(w, r, http.StatusInternalServerError, ErrorCode_INTERNAL_SERVER_ERROR.MessageObj())
		return
	}

	var id string
	if v := r.URL.Query().Get("id"); v == "" {
		respFail(w, r, http.StatusBadRequest, ErrorCode_BAD_REQUEST.MessageObjf("id param is required"))
		return
	} else {
		id = v
	}

	srv := h.ServerList.GetServerByID(id)
	if srv == nil {
		respFail(w, r, http.StatusForbidden, ErrorCode_UNAUTHORIZED_GAMESERVER.MessageObjf("no such game server"))
		return
	}
	if srv.Addr.Addr() != raddr.Addr() {
		respFail(w, r, http.StatusForbidden, ErrorCode_UNAUTHORIZED_GAMESERVER.MessageObj())
		return
	}
	h.ServerList.DeleteServerByID(id)

	respJSON(w, r, http.StatusForbidden, map[string]any{
		"success": true,
	})
}
