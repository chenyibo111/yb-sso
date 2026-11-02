package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/chenyibo111/yb-sso/internal/demo"
)

func main() {
	port := flag.Int("port", 3100, "demo app port: 3100 or 3101")
	flag.Parse()
	h, err := demo.New(context.Background(), *port)
	if err != nil {
		log.Fatal(err)
	}
	bind := os.Getenv("DEMO_BIND_ADDRESS")
	if bind == "" {
		bind = "127.0.0.1"
	}
	srv := &http.Server{Addr: bind + ":" + strconv.Itoa(*port), Handler: h, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("demo app listening on http://localhost:%d", *port)
	log.Fatal(srv.ListenAndServe())
}
