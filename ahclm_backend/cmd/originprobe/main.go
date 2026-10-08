// originprobe is a dedicated controlled origin. SIGHUP atomically reloads its
// certificate and writes a durable event that can be submitted to AHCLM.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"ahclm/internal/originprobe"
)

func main() {
	address := flag.String("listen", "127.0.0.1:8443", "HTTPS listen address; use :443 on a dedicated origin")
	cert := flag.String("cert", "", "certificate chain PEM")
	key := flag.String("key", "", "private key PEM")
	eventFile := flag.String("event", "origin-rotation.json", "latest rotation event file")
	flag.Parse()
	if *cert == "" || *key == "" {
		log.Fatal("-cert and -key are required")
	}
	o := originprobe.New()
	reload := func() error {
		event, err := o.Rotate(*cert, *key)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(event, "", "  ")
		if err != nil {
			return err
		}
		// Also retain the event in logs if disk persistence fails after reload.
		log.Printf("rotation_event %s", data)
		tmp, err := os.CreateTemp(filepath.Dir(*eventFile), ".origin-rotation-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(append(data, '\n')); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		return os.Rename(tmp.Name(), *eventFile)
	}
	if err := reload(); err != nil {
		log.Fatal(err)
	}
	server := o.Server(*address)
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for sig := range done {
			if sig == syscall.SIGHUP {
				if err := reload(); err != nil {
					log.Printf("reload/event error: %v", err)
				}
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = server.Shutdown(ctx)
			return
		}
	}()
	log.Printf("origin probe listening on %s%s", *address, originprobe.Path)
	if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
