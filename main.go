package main

import (
	"log"
	"net/http"

	"github.com/draiz/Learning/Signing/handlers"
	"github.com/gorilla/mux"
)

func main() {

	routers := mux.NewRouter()

	routers.HandleFunc("/signup", handlers.SignUp).Methods(http.MethodPost)
	routers.HandleFunc("/login", handlers.LogIn).Methods(http.MethodPost)
	routers.HandleFunc("/protected", handlers.TokenVerifyMiddleware(handlers.ProtectedEndpoint)).Methods(http.MethodGet)

	log.Fatal(http.ListenAndServe(":8000", routers))

}
