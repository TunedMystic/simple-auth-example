package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/TunedMystic/simple-auth-example/authsolo"
)

func indexHandler(w http.ResponseWriter, r *http.Request) {
	html := `
		<h1>the index page</h1>
		<p>
		<a href="/">Home</a>
		<a href="/dashboard">Dashboard</a>
		<a href="/about">About</a>
		<a href="/login">Login</a>
		<a href="/logout">Logout</a>
		</p>`

	fmt.Fprint(w, html)
}

func aboutHandler(w http.ResponseWriter, r *http.Request) {
	html := `
		<h1>the about page</h1>
		<p>
		<a href="/">Home</a>
		<a href="/dashboard">Dashboard</a>
		<a href="/about">About</a>
		<a href="/logout">Logout</a>
		</p>`

	fmt.Fprint(w, html)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	html := `
		<h1>the dashboard page</h1>
		<p>
		<a href="/">Home</a>
		<a href="/dashboard">Dashboard</a>
		<a href="/about">About</a>
		<a href="/logout">Logout</a>
		</p>`

	fmt.Fprint(w, html)
}

func main() {
	r := mux.NewRouter()
	auth := authsolo.Init("mypassword")

	r.HandleFunc("/", indexHandler)
	r.HandleFunc("/about", aboutHandler)
	r.HandleFunc("/dashboard", auth.Apply(dashboardHandler))
	r.PathPrefix("").Handler(auth.Routes())

	fmt.Println("Starting the app...")
	http.ListenAndServe("localhost:8000", r)
}
