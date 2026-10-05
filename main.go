package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)


type LoginAttempt struct{
	State string
	Verifier string
	ExpiresAt time.Time 
}

type Session struct{
	UserID string
	ExpiresAt time.Time
}


func main() {

	var mu sync.Mutex

	err1:= godotenv.Load()
	if err1!= nil{
		log.Fatal("Error while loading .env file")
	}

	provider , err2 := oidc.NewProvider(context.Background(), "https://accounts.google.com")
	if err2!= nil{
		log.Fatal("Error while loading Provider")
	}

	googleClientId, isGoogleClientIdPresent := os.LookupEnv("OAUTH_GOOGLE_CLIENT_ID") 
	googleClientSecret, isGoogleClientSecretPresent :=  os.LookupEnv("OAUTH_GOOGLE_CLIENT_SECRET")

	if !isGoogleClientIdPresent || !isGoogleClientSecretPresent || googleClientId == "" || googleClientSecret == "" {
		log.Fatal("Error, client id or client secret is missing in .env")
		return
	}

	var oidcConfig oidc.Config
	oidcConfig.ClientID = googleClientId

	idVerifier := provider.Verifier(&oidcConfig)


	loginMap := make(map[string]LoginAttempt)
	sessionMap := make(map[string]Session)

	var oauthConfig oauth2.Config

	oauthConfig.ClientID = googleClientId
	oauthConfig.ClientSecret = googleClientSecret
	oauthConfig.RedirectURL = "http://localhost:8080/callback"
	oauthConfig.Endpoint =  google.Endpoint
	oauthConfig.Scopes = []string{
		"openid",
		"email",
		"profile",
	}

	router:= gin.Default()

	// routes start here
	router.GET("/", func (ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message":"OAuth learning app",
		})
	})

	router.GET("/login", func (ctx *gin.Context) {
		// 1. creating a state
		stateBytes := make([]byte, 32)
		_, err := rand.Read(stateBytes)
		if err!=nil{
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"message":"Error while creating random bytes",
			})
			return
		}
		state := base64.RawURLEncoding.EncodeToString(stateBytes)

		// 2. creating a verifier
		verifier := oauth2.GenerateVerifier()

		// 3. Attempt ID generation same as state generation
		attemptBytes := make([]byte, 32)
		_, err1 := rand.Read(attemptBytes)
		if err1!=nil{
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"message":"Error while creating random bytes",
			})
			return
		}
		attemptId := base64.RawURLEncoding.EncodeToString(attemptBytes)

		loginAttempt := &LoginAttempt{
			State: state,
			Verifier: verifier,
			ExpiresAt: time.Now().Add(5*time.Minute),
		}

		// Locking while updloading to map.
		mu.Lock()
		loginMap[attemptId]=*loginAttempt
		mu.Unlock()

		// add the details to cookie
		http.SetCookie(ctx.Writer, &http.Cookie{
			Name: "oauth_login_attempt",
			Value: attemptId,
			Path: "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure: false,
			MaxAge: 300,
		})

		redirectionURL:= oauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

		ctx.Redirect(http.StatusFound, redirectionURL)
	})

	router.GET("/callback", func(ctx *gin.Context) {

		//vslidate the cookie
		cookie, err := ctx.Cookie("oauth_login_attempt")
		if err!= nil{
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message":"Cookie is missing..",
			})
			return
		}

		//Look up for the atttempt in map, if found delete
		mu.Lock()
		loginAttempt, exists := loginMap[cookie]
		if exists{
			delete(loginMap, cookie)
		}
		mu.Unlock()

		// delete the cookie
		http.SetCookie(ctx.Writer, &http.Cookie{
			Name: "oauth_login_attempt",
			Path: "/",
			MaxAge: -1,
		})

		if !exists{
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message":"Cookie is missing..",
			})
			return
		}

		currentTime :=  time.Now()
		cookieExpirationTime := loginAttempt.ExpiresAt

		if cookieExpirationTime.IsZero() || currentTime.After(cookieExpirationTime){
			//expired
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message":"cookie token expired.., relogin again",
			})
			return
		}

		state := ctx.Query("state")
		code := ctx.Query("code")
		errReq := ctx.Query("error")

		if state != loginAttempt.State{
			ctx.JSON(http.StatusBadRequest, gin.H{
				"message":"callback failed, mismatch state..",
			})
			return
		}

		if errReq !=""{
			ctx.JSON(http.StatusBadRequest, gin.H{
				"message":fmt.Sprintf("Error Found %s", errReq),
			})
			return
		}

		if state=="" || code==""{
			ctx.JSON(http.StatusBadRequest, gin.H{
				"message":"callback failed, missing state and code..",
			})
			return
		}

		// direct call to google for token exchange
		token, err := oauthConfig.Exchange(ctx.Request.Context(), code, oauth2.VerifierOption(loginAttempt.Verifier))
		if err != nil{
			ctx.JSON(http.StatusBadGateway, gin.H{
				"message":"Error while exchanging token..",
			})
			return
		}

		strToken, ok := token.Extra("id_token").(string)

		if !ok || strToken==""{
			ctx.JSON(http.StatusBadGateway, gin.H{
				"message":"Token is in invalid shape or missing",
			})
			return
		}

		verifierIDToken, err3 := idVerifier.Verify(ctx.Request.Context(), strToken)
		if err3 != nil{
			ctx.JSON(http.StatusBadGateway, gin.H{
				"message":"Error while verifying token..",
			})
			return
		}

		sessionToken := make([]byte, 32)
		_, errSession := rand.Read(sessionToken)
		if errSession !=nil{
			ctx.JSON(http.StatusInternalServerError, gin.H{
				"message":"Error while creating session.",
			})
			return
		}

		sessionTokenString := base64.RawURLEncoding.EncodeToString(sessionToken)

		if verifierIDToken.Subject ==""{
			ctx.JSON(http.StatusBadGateway, gin.H{
				"message":"Error suibject not found...",
			})
			return
		}
		session := &Session{
			UserID: verifierIDToken.Subject,
			ExpiresAt: time.Now().Add(1* time.Hour),
		}

		mu.Lock()
		sessionMap[sessionTokenString]=*session
		mu.Unlock()

		http.SetCookie(ctx.Writer, &http.Cookie{
			Name: "app_session",
			Value: sessionTokenString,
			Path: "/",
			MaxAge: 3600,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure: false,
		})

		ctx.JSON(http.StatusOK, gin.H{
			"message":"Login Successfull",
		})
	})

	router.GET("/me",func(ctx *gin.Context) {
		// need to read the token from the header
		cookie, err := ctx.Cookie("app_session")
		if err != nil{
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message":"Please Loign",
			})
			return
		}
		// if found, Lock and check the Map for expiry
		mu.Lock()
		session, exists := sessionMap[cookie]
		expired := exists && !time.Now().Before(session.ExpiresAt)
		if expired{
			delete(sessionMap, cookie)
		}
		mu.Unlock()

		if !exists || expired{
			// if session not found in map - clear the cookie 
			http.SetCookie(ctx.Writer, &http.Cookie{
				MaxAge: -1,
				Name: "app_session",
				Path: "/",	
			})

			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message":"Please login in ",
			})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{
			"userId":session.UserID,
		})


	})
	
	err:= router.Run(":8080")

	if err!=nil{
		log.Fatal("Error while running the Application...")
		return
	}
}