/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package main is the entrypoint for chromoting-healthcheck.
package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/jingyuanliang/chromoting-healthcheck/pkg/version"
	"github.com/shirou/gopsutil/v4/process"
	flag "github.com/spf13/pflag"
)

var (
	hostJSON = flag.String("host-json", "~/.config/chrome-remote-desktop/host#%s.json", "Path to find host JSON with %s for host hash")
	hostName = flag.String("host-name", "", "Host name used by chromoting to build host hash; defaults to os.Hostname()")
	bindAddr = flag.String("bind", ":15222", "Bind address for health and redirect")
	target   = flag.String("target", "https://remotedesktop.google.com/access/session/%s", "Redirect target address with %s for host ID")
	wantUser = flag.String("daemon-user", "root", "Name of the user running daemon")

	jsonPath string
)

type Host struct {
	ID string `json:"host_id"`
}

func getHost() (*Host, error) {
	f, err := os.Open(jsonPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	host := &Host{}
	return host, json.NewDecoder(f).Decode(host)
}

func health(w http.ResponseWriter, _ *http.Request) {
	host, err := getHost()
	if err != nil {
		log.Printf("Host JSON: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if host.ID == "" {
		log.Printf("Empty ID: %v", host)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	proc, err := process.Processes()
	if err != nil {
		log.Printf("Processes: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	for _, p := range proc {
		user, err := p.Username()
		if err != nil {
			log.Printf("Username of %d: %v", p.Pid, err)
			continue
		}
		if user != *wantUser {
			continue
		}

		cmdline, err := p.Cmdline()
		if err != nil {
			log.Printf("Cmdline of %d: %v", p.Pid, err)
			continue
		}
		if !strings.Contains(cmdline, jsonPath) {
			continue
		}

		return
	}

	log.Printf("Not found after checking %d processes.", len(proc))
	w.WriteHeader(http.StatusInternalServerError)
}

func redirect(w http.ResponseWriter, r *http.Request) {
	host, err := getHost()
	if err != nil {
		log.Printf("Host JSON: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf(*target, host.ID), http.StatusFound)
}

func main() {
	log.Printf("version: %s\n", version.Version)

	flag.Parse()
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		log.Printf("FLAG: --%s=%q", f.Name, f.Value)
	})

	host := *hostName
	var err error
	if host == "" {
		host, err = os.Hostname()
		if err != nil {
			log.Fatalf("Hostname: %v", err)
		}
	}
	log.Printf("Using host: %s", host)

	md5sum := md5.Sum([]byte(host))
	hash := hex.EncodeToString(md5sum[:])
	log.Printf("Using hash: %s", hash)

	jsonPath = fmt.Sprintf(*hostJSON, hash)
	if strings.HasPrefix(jsonPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("UserHomeDir: %v", err)
		}
		jsonPath = filepath.Join(home, jsonPath[2:])
	}
	log.Printf("Using json: %s", jsonPath)

	http.HandleFunc("/health", health)
	http.HandleFunc("/redirect", redirect)
	log.Printf("Listening at %s", *bindAddr)
	log.Fatal(http.ListenAndServe(*bindAddr, handlers.LoggingHandler(os.Stderr, http.DefaultServeMux)))
}
