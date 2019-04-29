package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
	uuid "github.com/satori/go.uuid"
)

const (
	sessionLength int = 60
)

// User db user info
type User struct {
	UserName string
	Email    string
	PassWord string
}

// SessionInfo session value info
type SessionInfo struct {
	UserEmail    string
	LastActivity time.Time
}

// Sessions db session info
type Sessions map[string]SessionInfo // cookie uuid: User.email
// type sessionPool map[string]Sessions

var dbSessions = map[string]SessionInfo{}

var sessionPool = make([]Sessions, 10)

// db user info
// var dbUsers = map[string]User{} // user.email: User struct

var tpl *template.Template

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))

}

func main() {

	http.HandleFunc("/", index)
	http.HandleFunc("/login", login)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/auth", auth)
	http.HandleFunc("/logout", logout)
	http.Handle("/favicon.ico", http.NotFoundHandler())

	fmt.Println("Server starting at port 8080...")
	http.ListenAndServe(":8080", nil)
}

func alreadyLoggedIn(w http.ResponseWriter, r *http.Request) bool {
	// check cookie
	cookie, err := r.Cookie("session")
	if err != nil {
		return false
	}
	// check session
	for i, s := range sessionPool {

		// check if session uuid exists in sessionPool
		if _, ok := s[cookie.Value]; ok {
			// renew MaxAge for loggedin user.
			cookie.MaxAge = sessionLength
			http.SetCookie(w, cookie)
			fmt.Println(i, s)
			return ok
		}
	}
	return false

}

func dbConn() *sql.DB {
	db, err := sql.Open("mysql", "root:leaf@tcp(127.0.0.1:3306)/")
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec("CREATE DATABASE IF NOT EXISTS leaf")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec("USE leaf")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS userinfo (
		useremail VARCHAR(64) NOT NULL,
		username VARCHAR(64) NOT NULL,
		password VARCHAR(64) NOT NULL,
		PRIMARY KEY (useremail));
	  
	`)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Successfully created database..")
	fmt.Println("Database Connected")

	return db
}

func index(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		tpl.ExecuteTemplate(w, "index.html", nil)
		return
	}

	for _, s := range sessionPool {
		if sessioninfo, ok := s[cookie.Value]; ok {
			tpl.ExecuteTemplate(w, "index.html", sessioninfo)
			return
		}
	}

	tpl.ExecuteTemplate(w, "index.html", nil)

}

func login(w http.ResponseWriter, r *http.Request) {
	if alreadyLoggedIn(w, r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		db := dbConn()
		defer db.Close()
		r.ParseForm()
		email := r.PostForm.Get("email")
		password := r.PostForm.Get("password")
		// check empty field
		if email == "" || password == "" {
			http.Error(w, "field empty", http.StatusForbidden)
			return
		}

		// check if user already exists
		var pw string
		err := db.QueryRow("SELECT password FROM userinfo WHERE useremail=?", email).Scan(&pw)
		if err != nil {
			if err == sql.ErrNoRows {
				// not exit in database
				http.Error(w, "user does not exist", http.StatusForbidden)
				return
			} else {
				log.Fatal(err)
			}
		}

		// if u.PassWord == password {

		// 	sID, err := uuid.NewV4()
		// 	if err != nil {
		// 		log.Fatal(err)
		// 	}
		// 	cookie := &http.Cookie{
		// 		Name:  "session",
		// 		Value: sID.String(),
		// 	}
		// 	http.SetCookie(w, cookie)

		// 	dbSessions[cookie.Value] = SessionInfo{email, time.Now()}
		// 	sessionPool = append(sessionPool, dbSessions)
		// 	fmt.Println(sessionPool)

		// 	http.Redirect(w, r, "/index", http.StatusSeeOther)

		// } else {
		// 	http.Error(w, "wrong password or/and email", http.StatusForbidden)
		// 	return
		// }

		// hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		// if err != nil {
		// 	http.Error(w, "Server error, unable to create your account", http.StatusInternalServerError)
		// 	return
		// }

		err = bcrypt.CompareHashAndPassword([]byte(pw), []byte(password))
		if err != nil {
			http.Error(w, "email and/or password do not match", http.StatusForbidden)
			return
		} else {

			sID, err := uuid.NewV4()
			if err != nil {
				log.Fatal(err)
			}
			cookie := &http.Cookie{
				Name:  "session",
				Value: sID.String(),
			}
			http.SetCookie(w, cookie)

			dbSessions[cookie.Value] = SessionInfo{email, time.Now()}
			sessionPool = append(sessionPool, dbSessions)
			fmt.Println(sessionPool)

			http.Redirect(w, r, "/index", http.StatusSeeOther)

		}

		// check if user already exists

		// var isAuthenticated bool
		// err = db.QueryRow("SELECT IF(COUNT(*), 'true', 'false') FROM userinfo WHERE useremail=? AND password=?", email, hashedPassword).Scan(&isAuthenticated)
		// if err != nil {
		// 	log.Fatal(err)
		// }

		// if isAuthenticated {
		// 	sID, err := uuid.NewV4()
		// 	if err != nil {
		// 		log.Fatal(err)
		// 	}
		// 	cookie := &http.Cookie{
		// 		Name:  "session",
		// 		Value: sID.String(),
		// 	}
		// 	http.SetCookie(w, cookie)

		// 	dbSessions[cookie.Value] = SessionInfo{email, time.Now()}
		// 	sessionPool = append(sessionPool, dbSessions)
		// 	fmt.Println(sessionPool)

		// 	http.Redirect(w, r, "/index", http.StatusSeeOther)
		// 	return
		// }

	}
	tpl.ExecuteTemplate(w, "login.html", nil)
}

func signup(w http.ResponseWriter, r *http.Request) {
	db := dbConn()
	defer db.Close()

	if r.Method == http.MethodGet {
		cookie, err := r.Cookie("session")
		if err != nil {
			tpl.ExecuteTemplate(w, "signup.html", nil)
			return
		}
		if _, ok := dbSessions[cookie.Value]; ok {
			http.Redirect(w, r, "/index", http.StatusSeeOther)
			return
		} else if !ok {
			tpl.ExecuteTemplate(w, "signup.html", nil)
			return
		}
	}

	if r.Method == http.MethodPost {

		r.ParseForm()
		username := r.PostForm.Get("username")
		email := r.PostForm.Get("email")
		password := r.PostForm.Get("password")
		// check empty field
		if email == "" || password == "" || username == "" {
			http.Error(w, "field empty", http.StatusForbidden)
			return
		}

		// check if user already exists
		var un string
		err := db.QueryRow("SELECT username FROM userinfo WHERE username=? OR useremail=?", username, email).Scan(&un)

		// check if have any error
		if err != nil {
			if err == sql.ErrNoRows {
				// there were no rows, but otherwise no error occurred

				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				if err != nil {
					http.Error(w, "Server error, unable to create your account", http.StatusInternalServerError)
					return
				}
				strPassword := string(hashedPassword)
				stmt, err := db.Prepare("INSERT INTO userinfo(username, useremail, password) VALUES(?, ?, ?)")
				if err != nil {
					log.Fatal(err)
				}
				defer stmt.Close()
				res, err := stmt.Exec(username, email, strPassword)
				if err != nil {
					log.Fatal(err)
				}
				lastID, err := res.LastInsertId()
				if err != nil {
					log.Fatal(err)
				}
				rowCnt, err := res.RowsAffected()
				if err != nil {
					log.Fatal(err)
				}
				log.Printf("ID = %d, affected = %d\n", lastID, rowCnt)

				sID, err := uuid.NewV4()
				if err != nil {
					log.Fatal(err)
				}
				cookie := &http.Cookie{
					Name:  "session",
					Value: sID.String(),
				}
				http.SetCookie(w, cookie)

				dbSessions[cookie.Value] = SessionInfo{email, time.Now()}
				sessionPool = append(sessionPool, dbSessions)
				fmt.Println(sessionPool)

				http.Redirect(w, r, "/index", http.StatusSeeOther)

			} else {
				log.Fatal(err)
			}
		} else {
			http.Error(w, "account already exited", http.StatusInternalServerError)
			return
		}

		// 	http.Error(w, "user already exists", http.StatusForbidden)
		// 	return

		// sID, err := uuid.NewV4()
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// cookie := &http.Cookie{
		// 	Name:  "session",
		// 	Value: sID.String(),
		// }
		// http.SetCookie(w, cookie)

		// u = User{username, email, password}
		// dbSessions[cookie.Value] = SessionInfo{email, time.Now()}
		// sessionPool = append(sessionPool, dbSessions)
		// dbUsers[email] = u
		// fmt.Println(sessionPool)

		// http.Redirect(w, r, "/index", http.StatusSeeOther)
		// return

	}

}

func logout(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/index", http.StatusSeeOther)
		return
	}
	if _, ok := dbSessions[cookie.Value]; ok {

		delete(dbSessions, cookie.Value)
		cookie.MaxAge = -1
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

}

func auth(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/index", http.StatusSeeOther)
		return
	}

	for _, s := range sessionPool {
		if sessioninfo, ok := s[cookie.Value]; ok {
			tpl.ExecuteTemplate(w, "auth.html", sessioninfo)
			return
		}
	}
	http.Redirect(w, r, "/index", http.StatusSeeOther)
}
