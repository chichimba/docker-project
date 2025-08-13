// insecure/vuln_demo.go
// ⚠️ ТОЛЬКО ДЛЯ ТЕСТИРОВАНИЯ СКАНЕРА. НЕ ИСПОЛЬЗОВАТЬ В ПРОДАКШЕНЕ.
package main

import (
	"crypto/md5"          // VULN: Weak hash for passwords
	"crypto/tls"          // VULN: InsecureSkipVerify
	"database/sql"        // VULN: Unsafe string-concatenated SQL
	"fmt"                 // VULN: XSS via unescaped echo
	"net/http"
	"os"                  // VULN: Overly permissive perms
	"os/exec"             // VULN: Command injection
)

var (
	// VULN: Hardcoded secret
	jwtSecret = "supersecret-DO-NOT-COMMIT"

	// touch import so it compiles even without a driver
	_ = sql.ErrNoRows
)

// VULN: SQL Injection — builds query by concatenation
func handlerSQLi(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	query := "SELECT * FROM users WHERE name = '" + user + "'" // VULN
	// pretend to use it:
	fmt.Println("Executing:", query)
	fmt.Fprintln(w, "ok")
}

// VULN: Command Injection — executes user-supplied shell
func handlerCmd(w http.ResponseWriter, r *http.Request) {
	cmdStr := r.URL.Query().Get("cmd")
	out, _ := exec.Command("bash", "-lc", cmdStr).CombinedOutput() // VULN
	w.Write(out)
}

// VULN: Path Traversal — serves arbitrary paths like ?file=../../etc/passwd
func handlerTraversal(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	http.ServeFile(w, r, "./public/"+file) // VULN
}

// VULN: Insecure TLS — skips certificate verification
func handlerInsecureTLS(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // VULN
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	fmt.Fprintln(w, "fetched:", resp.Status)
}

// VULN: Reflected XSS — directly echos user input into HTML
func handlerXSS(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	fmt.Fprintf(w, q) // VULN
}

// VULN: Open Redirect — redirects to arbitrary URL
func handlerRedirect(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, next, http.StatusFound) // VULN
}

// VULN: Weak crypto — MD5 for password hashing
func handlerWeakHash(w http.ResponseWriter, r *http.Request) {
	pwd := r.URL.Query().Get("pwd")
	sum := md5.Sum([]byte(pwd)) // VULN
	fmt.Fprintf(w, "md5=%x", sum)
}

// VULN: Overly permissive file permissions
func handlerPerms(w http.ResponseWriter, r *http.Request) {
	_ = os.WriteFile("/tmp/app.log", []byte("test"), 0o777) // VULN
	fmt.Fprintln(w, "wrote /tmp/app.log")
}

func main() {
	http.HandleFunc("/sqli", handlerSQLi)
	http.HandleFunc("/cmd", handlerCmd)
	http.HandleFunc("/file", handlerTraversal)
	http.HandleFunc("/fetch", handlerInsecureTLS)
	http.HandleFunc("/xss", handlerXSS)
	http.HandleFunc("/redirect", handlerRedirect)
	http.HandleFunc("/md5", handlerWeakHash)
	http.HandleFunc("/perms", handlerPerms)
	_ = http.ListenAndServe(":8080", nil)
}
