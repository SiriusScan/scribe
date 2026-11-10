// Command fixture serves a local marker used by the original example script.
package main

import (
	"log"
	"net/http"
	"time"
)

func main() {
	server := &http.Server{
		Addr:              "127.0.0.1:8080",
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Sirius-Fixture", "vulnerable")
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("Scribe local demonstration fixture\n"))
		}),
	}
	log.Printf("serving the demonstration fixture at http://%s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
