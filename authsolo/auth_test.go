package authsolo

import (
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type TestFunc func(*testing.T)

func Test_GetHash(t *testing.T) {
	type test struct {
		text     string
		expected string
	}

	tests := []test{
		{"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{"hi", "c22b5f9178342609428d6f51b2c5af4c0bde6a42"},
		{"password", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"},
	}

	for _, testItem := range tests {
		t.Run(testItem.text, func(t *testing.T) {
			if r := getHash(testItem.text); r != testItem.expected {
				t.Errorf("expected %v, got %v\n", testItem.expected, r)
			}
		})
	}
}

func Test_Init(t *testing.T) {
	a := Init("password")

	expectedHash := "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
	if a.hash != expectedHash {
		t.Errorf("expected %v, got %v\n", a.hash, expectedHash)
	}

	if a.loginURL != "/login" {
		t.Errorf("expected /login, got %v\n", a.loginURL)
	}

	if a.afterLogin != "/" {
		t.Errorf("expected /, got %v\n", a.afterLogin)
	}

	if a.nextParam != "next" {
		t.Errorf("expected next, got %v\n", a.nextParam)
	}

	if a.cookieName != "user" {
		t.Errorf("expected user, got %v\n", a.cookieName)
	}
}

func Test_Login(t *testing.T) {
	a := Init("password")
	expectedHash := "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"

	w := httptest.NewRecorder()

	a.Login(w, a.hash)

	// Get the cookie from the ResponseWriter.
	cookie := w.Result().Cookies()[0]

	// Check cookie values.
	if cookie.Name != "user" {
		t.Errorf("expected user, got %v\n", cookie.Name)
	}

	if cookie.Value != expectedHash {
		t.Errorf("expected %v, got %v\n", expectedHash, cookie.Value)
	}

	if cookie.MaxAge != 14400 {
		t.Errorf("expected 14400, got %v\n", cookie.MaxAge)
	}

	if !cookie.HttpOnly {
		t.Errorf("expected true, got %v\n", cookie.HttpOnly)
	}

	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected %v, got %v\n", http.SameSiteStrictMode, cookie.SameSite)
	}
}

func Test_Logout(t *testing.T) {
	a := Init("password")

	w := httptest.NewRecorder()

	a.Logout(w)

	// Get the cookie from the ResponseWriter.
	cookie := w.Result().Cookies()[0]

	// Check cookie values.
	if cookie.Name != "user" {
		t.Errorf("expected user, got %v\n", cookie.Name)
	}

	if cookie.Value != "" {
		t.Errorf("expected empty string, got %v\n", cookie.Value)
	}

	if cookie.MaxAge != -1 {
		t.Errorf("expected -1, got %v\n", cookie.MaxAge)
	}

	if !cookie.HttpOnly {
		t.Errorf("expected true, got %v\n", cookie.HttpOnly)
	}

	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("expected %v, got %v\n", http.SameSiteStrictMode, cookie.SameSite)
	}
}

func Test_IsAuthenticated(t *testing.T) {
	a := Init("password")

	// Perform the login.
	w := httptest.NewRecorder()
	a.Login(w, a.hash)

	// Add the cookie to an http.Request object.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(w.Result().Cookies()[0])

	loggedIn := a.IsAuthenticated(r)
	if !loggedIn {
		t.Errorf("expected true, got %v\n", loggedIn)
	}
}

func Test_IsAuthenticated__fails_when_cookie_not_set(t *testing.T) {
	a := Init("password")

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	loggedIn := a.IsAuthenticated(r)
	if loggedIn {
		t.Errorf("expected false, got %v\n", loggedIn)
	}
}

func Test_IsAuthenticated__fails_when_hash_mismatch(t *testing.T) {
	a := Init("password")

	// Perform the login.
	w := httptest.NewRecorder()
	a.Login(w, a.hash)

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	// Set bad value, and add cookie to request.
	cookie := w.Result().Cookies()[0]
	cookie.Value = "bad-hash"
	r.AddCookie(cookie)

	loggedIn := a.IsAuthenticated(r)
	if loggedIn {
		t.Errorf("expected false, got %v\n", loggedIn)
	}
}

func Test_LoginFormHTML(t *testing.T) {
	a := Init("password")

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	loginForm := a.LoginFormHTML(r)
	expectedLoginForm := `
		<form class="login-form" method="post" action="/login">
			<input type="password" placeholder="password" name="password">
			<input type="hidden" name="next" value="/">
			<button type="submit">Login</button>
		</form>`

	if compress(loginForm) != compress(expectedLoginForm) {
		t.Errorf("expected %v\n, got %v\n", expectedLoginForm, loginForm)
	}
}

func Test_LoginFormHTML__custom_next_param(t *testing.T) {
	a := Init("password")

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	// Query params
	q := url.Values{}
	q.Add("next", "/dashboard")
	r.URL.RawQuery = q.Encode()

	loginForm := a.LoginFormHTML(r)
	expectedLoginForm := `
		<form class="login-form" method="post" action="/login">
			<input type="password" placeholder="password" name="password">
			<input type="hidden" name="next" value="/dashboard">
			<button type="submit">Login</button>
		</form>`

	if compress(loginForm) != compress(expectedLoginForm) {
		t.Errorf("expected %v\n, got %v\n", expectedLoginForm, loginForm)
	}
}

func Test_LoginFormHTML__rendering_error(t *testing.T) {
	a := Init("password")
	a.loginFormTemplate = template.Must(template.New("").Parse("{{.BadTemplateValue}}"))

	r := httptest.NewRequest(http.MethodGet, "/", nil)

	loginForm := a.LoginFormHTML(r)

	if loginForm != "" {
		t.Errorf("expected empty string, got %v\n", loginForm)
	}
}

func Test_HandleLogin_Get(t *testing.T) {
	a := Init("password")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	http.HandlerFunc(a.HandleLogin).ServeHTTP(w, r)

	expectedLoginForm := `
		<html>
		<form class="login-form" method="post" action="/login">
			<input type="password" placeholder="password" name="password">
			<input type="hidden" name="next" value="/">
			<button type="submit">Login</button>
		</form>
		</html>`

	body := w.Body.String()

	if compress(body) != compress(expectedLoginForm) {
		t.Errorf("expected %v\n, got %v\n", expectedLoginForm, body)
	}
}

func Test_HandleLogin_Get__already_authenticated(t *testing.T) {
	a := Init("password")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ww := httptest.NewRecorder()

	a.Login(ww, a.hash)

	// Add the cookie to an http.Request object.
	r.AddCookie(ww.Result().Cookies()[0])

	w := httptest.NewRecorder()

	http.HandlerFunc(a.HandleLogin).ServeHTTP(w, r)

	// When user is already authenticated, navigating to the
	// login URL should redirect them to the afterLogin URL

	// Check redirect status code.
	if w.Code != http.StatusFound {
		t.Errorf("expected %v\n, got %v\n", http.StatusFound, w.Code)
	}

	// Check redirect url location
	url, err := w.Result().Location()
	if err != nil {
		t.Errorf("error when getting response location: %v\n", err.Error())
	}

	if url.Path != a.afterLogin {
		t.Errorf("expected %v\n, got %v\n", a.afterLogin, url.Path)
	}
}

func Test_HandleLogin_Post(t *testing.T) {
	a := Init("supersecret")

	reader := strings.NewReader("password=supersecret")
	r := httptest.NewRequest(http.MethodPost, "/", reader)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	http.HandlerFunc(a.HandleLogin).ServeHTTP(w, r)

	// Check redirect status code.
	if w.Code != http.StatusFound {
		t.Errorf("expected %v\n, got %v\n", http.StatusFound, w.Code)
	}

	// Check redirect url location
	url, err := w.Result().Location()
	if err != nil {
		t.Errorf("error when getting response location: %v\n", err.Error())
	}

	if url.Path != a.afterLogin {
		t.Errorf("expected %v\n, got %v\n", a.afterLogin, url.Path)
	}

	// Check cookie value
	cookie := w.Result().Cookies()[0]

	if cookie.Value != a.hash {
		t.Errorf("expected %v\n, got %v\n", a.hash, cookie.Value)
	}
}

func Test_HandleLogin_Post__custom_next_param(t *testing.T) {
	a := Init("supersecret")

	type test struct {
		next          string
		redirLocation string
	}

	tests := []test{
		{"", "/"},
		{a.loginURL, "/"},
		{"/dashboard", "/dashboard"},
	}

	getSubTestFunc := func(testItem test) TestFunc {
		return func(t *testing.T) {
			reader := strings.NewReader("password=supersecret")
			r := httptest.NewRequest(http.MethodPost, "/", reader)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			// Query params
			q := url.Values{}
			q.Add("next", testItem.next)
			r.URL.RawQuery = q.Encode()

			w := httptest.NewRecorder()

			http.HandlerFunc(a.HandleLogin).ServeHTTP(w, r)

			// Check redirect status code.
			if w.Code != http.StatusFound {
				t.Errorf("expected %v\n, got %v\n", http.StatusFound, w.Code)
			}

			// Check redirect url location
			url, err := w.Result().Location()
			if err != nil {
				t.Errorf("error when getting response location: %v\n", err.Error())
			}

			if url.Path != testItem.redirLocation {
				t.Errorf("expected %v\n, got %v\n", a.afterLogin, testItem.redirLocation)
			}

			// Check cookie value
			cookie := w.Result().Cookies()[0]

			if cookie.Value != a.hash {
				t.Errorf("expected %v\n, got %v\n", a.hash, cookie.Value)
			}
		}
	}

	for _, testItem := range tests {
		testName := fmt.Sprintf("[%v=%v]?", testItem.next, testItem.redirLocation)
		subTestFunc := getSubTestFunc(testItem)
		t.Run(testName, subTestFunc)
	}
}

func Test_HandleLogin_Post__invalid_password(t *testing.T) {
	a := Init("supersecret")

	reader := strings.NewReader("password=badpassword")
	r := httptest.NewRequest(http.MethodPost, "/", reader)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	http.HandlerFunc(a.HandleLogin).ServeHTTP(w, r)

	// Check redirect status code.
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %v\n, got %v\n", http.StatusFound, w.Code)
	}
}

func Test_HandleLogout(t *testing.T) {
	a := Init("password")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	http.HandlerFunc(a.HandleLogout).ServeHTTP(w, r)

	// Check redirect status code.
	if w.Code != http.StatusFound {
		t.Errorf("expected %v\n, got %v\n", http.StatusFound, w.Code)
	}

	// Check cookie value
	cookie := w.Result().Cookies()[0]

	if cookie.Value != "" {
		t.Errorf("expected empty string, got %v\n", cookie.Value)
	}

	if cookie.MaxAge != -1 {
		t.Errorf("expected empty -1, got %v\n", cookie.MaxAge)
	}
}

func Test_Apply(t *testing.T) {
	a := Init("password")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	ww := httptest.NewRecorder()

	a.Login(ww, a.hash)

	// Add the cookie to an http.Request object.
	r.AddCookie(ww.Result().Cookies()[0])

	w := httptest.NewRecorder()

	handlerReached := false

	h := func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		fmt.Fprint(w, "We're in!")
	}

	http.HandlerFunc(a.Apply(h)).ServeHTTP(w, r)

	// Check redirect status code.
	if w.Code != http.StatusOK {
		t.Errorf("expected %v\n, got %v\n", http.StatusOK, w.Code)
	}

	if !handlerReached {
		t.Errorf("expected true, got %v\n", handlerReached)
	}
}

func Test_Apply__auth_failed(t *testing.T) {
	a := Init("password")
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	handlerReached := false

	h := func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		fmt.Fprint(w, "We're in!")
	}

	http.HandlerFunc(a.Apply(h)).ServeHTTP(w, r)

	// Check redirect status code.
	if w.Code != http.StatusFound {
		t.Errorf("expected %v\n, got %v\n", http.StatusFound, w.Code)
	}

	if handlerReached {
		t.Errorf("expected false, got %v\n", handlerReached)
	}
}

func Test_Routes(t *testing.T) {
	a := Init("password")
	authRoutes := a.Routes()

	r := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	http.Handler(authRoutes).ServeHTTP(w, r)
}

// ------------------------------------------------------------------
// Test Helpers
// ------------------------------------------------------------------

func compress(text string) string {
	s := []string{}

	for _, item := range strings.Split(text, "\n") {
		s = append(s, strings.TrimSpace(item))
	}

	return strings.Join(s, "")
}
