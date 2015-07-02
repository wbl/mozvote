package main

import (
	"log"
	"net/http"
)

var votes chan string

func MainServer(w http.ResponseWriter, req *http.Request) {
	http.ServeFile(w, req, "insecure.html")
}

func VoteServer(w http.ResponseWriter, req *http.Request) {
	val := req.FormValue("vote")
	log.Printf("Observed vote %s from User Agent %s\n", val, req.UserAgent())
	votes <- val
	w.WriteHeader(http.StatusOK)
}

func collect() {
	tea := 0
	coffee := 0
	for vote := range votes {
		if vote == "tea" {
			tea++
		} else if vote == "coffee" {
			coffee++
		}
		log.Println("tea: ", tea, "coffe: ", coffee)
	}
}

func main() {
	votes = make(chan string)
	go collect()
	http.HandleFunc("/", MainServer)
	http.Handle("/static/",
		http.StripPrefix("/static/",
			http.FileServer(http.Dir("static/"))))
	http.HandleFunc("/vote/", VoteServer)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Listen and Serve: ", err)
	}
}
