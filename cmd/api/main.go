package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/greg-frost/go-avito/internal/auth"
	"github.com/greg-frost/go-avito/internal/db/postgres"
	"github.com/greg-frost/go-avito/internal/handler"

	"github.com/gorilla/mux"
)

func main() {
	fmt.Println(" \n[ AVITO INTERNSHIP ]\n ")

	addr := flag.String("addr", "localhost", "server address")
	port := flag.Int("port", 8080, "server port")
	flag.Parse()

	router := mux.NewRouter()

	pgParams := postgres.ConnectionParams{
		DbName:   os.Getenv("DB_NAME"),
		User:     os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASS"),
	}
	pgStorage, err := postgres.NewStorage(pgParams)
	if err != nil {
		log.Fatal(err)
	}

	muxHandler := handler.NewHandler(pgStorage)
	muxHandler.Register(router)

	router.Use(auth.JwtAuthentication)

	startServer(router, fmt.Sprintf("%s:%d", *addr, *port))
}

func startServer(router *mux.Router, connAddr string) {
	listener, err := net.Listen("tcp", connAddr)
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Handler:      router,
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
	}

	fmt.Println("Listening for connections...")
	fmt.Println("(on http://" + connAddr + ")")
	log.Fatal(server.Serve(listener))
}
