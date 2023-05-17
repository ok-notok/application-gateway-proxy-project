package main

import (
	"log"
	"net/http"
)

func main() {
	log.Println("Listening on Port 8082...")
	http.Handle("/", http.FileServer(http.Dir("/Users/alperaslan/project439/files/")))
	log.Fatal(http.ListenAndServe(":8082", nil))
}
