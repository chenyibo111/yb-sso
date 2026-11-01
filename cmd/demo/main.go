package main

import (
	"context"
	"flag"
	"log"
	"net/http"
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
	srv := &http.Server{Addr: "127.0.0.1:" + strconv.Itoa(*port), Handler: h, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("demo app listening on http://localhost:%d", *port)
	log.Fatal(srv.ListenAndServe())
}
