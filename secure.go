package main

import (
	"bufio"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"vote"
)

type Ballot struct {
	tea    *vote.Mark
	coffee *vote.Mark
}

var votes chan Ballot

func MainServer(w http.ResponseWriter, req *http.Request) {
	http.ServeFile(w, req, "secure.html")
}

func VoteServer(w http.ResponseWriter, req *http.Request) {
	teabase := req.FormValue("tea")
	coffeebase := req.FormValue("coffee")
	log.Println("Recieved only ", teabase, " and ", coffeebase)
	c := elliptic.P256()
	public, err := base64.StdEncoding.DecodeString("BFqcfyJcH+Bx7xA9YjSxYXyVR5FIQeIH+XbeIZot+jIMnYH8nX5aOY397xXUOZiwzYvWFELsMJeSMSIHkHyR5K0=")
	if err != nil {
		panic("Bad public key")
	}
	px, py := elliptic.Unmarshal(c, public)
	var ballot Ballot
	teabytes, err := base64.StdEncoding.DecodeString(teabase)
	if err != nil {
		log.Println("Bad base 64")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	coffeebytes, err := base64.StdEncoding.DecodeString(coffeebase)
	if err != nil {
		log.Println("Bad base 64")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	teavote := vote.UnmarshalCheckbox(c, teabytes)
	coffeevote := vote.UnmarshalCheckbox(c, coffeebytes)
	if !vote.IsValidBox(c, teavote, px, py) ||
		!vote.IsValidBox(c, coffeevote, px, py) {
		log.Println("Bad proof")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ballot.tea = vote.ExtractMark(teavote)
	ballot.coffee = vote.ExtractMark(coffeevote)
	votes <- ballot
	w.WriteHeader(http.StatusOK)
}

func collect() {
	c := elliptic.P256()
	var tottea *vote.Mark
	var totcoffee *vote.Mark
	valid := false
	for ballot := range votes {
		if valid {
			tottea = vote.AddMarks(c, tottea, ballot.tea)
			totcoffee = vote.AddMarks(c, totcoffee, ballot.coffee)
		} else {
			tottea = ballot.tea
			totcoffee = ballot.coffee
			valid = true
		}
		teabase := base64.StdEncoding.EncodeToString(
			vote.MarshalMark(c, tottea))
		coffeebase := base64.StdEncoding.EncodeToString(
			vote.MarshalMark(c, totcoffee))
		log.Printf("Sending %s, %s to third party.\n",
			teabase, coffeebase)
		file, err := os.Create("votes.tmp")
		if err != nil {
			log.Printf("Unable to transmit votes:%s\n", err.Error())
			continue
		}
		file.WriteString(fmt.Sprintf("tea:%s\ncoffee:%s\n",
			teabase, coffeebase))
		file.Close()
		os.Rename("votes.tmp", "votes")
	}
}

func ResultsServer(w http.ResponseWriter, req *http.Request) {
	c := elliptic.P256()
	priv, err := hex.DecodeString("71f8d90c7900c1fb3b80a9bed8783f5527533be09fee785a70e41144b6b4a35f")
	if err != nil {
		panic("Bad private key")
	}
	file, err := os.Open("votes")
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(file)
	var line string
	results := make(map[string]int)
	for scanner.Scan() {
		line = scanner.Text()
		parts := strings.Split(line, ":")
		name := parts[0]
		t, _ := base64.StdEncoding.DecodeString(parts[1])
		ballot := vote.UnmarshalMark(c, t)
		result, _ := vote.DecryptMark(c, ballot, priv)
		log.Printf("Third party saw %s", line)
		results[name] = result
	}
	w.Header().Set("Content-Type","application/json")
	res, _ := json.Marshal(results)
	w.Write(res)
}

func main() {
	votes = make(chan Ballot, 10)
	go collect()
	http.HandleFunc("/", MainServer)
	http.Handle("/static/",
		http.StripPrefix("/static/",
			http.FileServer(http.Dir("static/"))))
	http.HandleFunc("/vote/", VoteServer)
	http.HandleFunc("/results/", ResultsServer)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Listen and Serve: ", err)
	}
}
