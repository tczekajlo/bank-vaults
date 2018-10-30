// Copyright © 2018 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"encoding/base32"
	"fmt"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	jwtRequest "github.com/dgrijalva/jwt-go/request"
	"github.com/gin-gonic/gin"
	"github.com/qor/qor/utils"
)

// CurrentUser context key to get current user from Request
const CurrentUser utils.ContextKey = "current_user"

// TokenType represents one of the possible token Types
type TokenType string

// ClaimConverter converts claims to another domain object for saving into Context
type ClaimConverter func(*ScopedClaims) interface{}

// ScopedClaims struct to store the scoped claim related things
type ScopedClaims struct {
	jwt.StandardClaims
	Scope string `json:"scope,omitempty"`
	// Drone fields
	Type TokenType `json:"type,omitempty"`
	Text string    `json:"text,omitempty"`
}

type options struct {
	claimConverter  ClaimConverter
	extractors      []jwtRequest.Extractor
	externalIssuers map[string]bool
}

func (opts *options) apply(authOptions []AuthOption) {
	for _, authOption := range authOptions {
		authOption(opts)
	}
}

// AuthOption allows setting optional attributes when
// creating a JWTAuth Handler.
type AuthOption func(*options)

// WithClaimConverter adds a claim converter which converts the
// ScopedClaims type claims before saving to the gin.Context
func WithClaimConverter(claimConverter ClaimConverter) AuthOption {
	return func(opts *options) {
		opts.claimConverter = claimConverter
	}
}

// WithJWTExtractor adds an extra JWT extractor to the options
func WithJWTExtractor(extractor jwtRequest.Extractor) AuthOption {
	return func(opts *options) {
		opts.extractors = append(opts.extractors, extractor)
	}
}

// WithExternalIssuer adds allowed external JWT issuers to the options
func WithExternalIssuer(issuer string) AuthOption {
	return func(opts *options) {
		opts.externalIssuers[issuer] = true
	}
}

// JWTAuth returns a new JWT authentication handler
func JWTAuth(tokenStore TokenStore, signingKey string, authOptions ...AuthOption) gin.HandlerFunc {

	opts := options{externalIssuers: map[string]bool{}}
	opts.apply(authOptions)

	signingKeyBase32 := []byte(base32.StdEncoding.EncodeToString([]byte(signingKey)))

	hmacKeyFunc := func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Method.Alg())
		}
		return signingKeyBase32, nil
	}

	extractor := jwtRequest.MultiExtractor{jwtRequest.OAuth2Extractor}
	for _, e := range opts.extractors {
		extractor = append(extractor, e)
	}

	return func(c *gin.Context) {

		var claims ScopedClaims
		// this checks if token has expired, badly signed, badly formatted
		_, err := jwtRequest.ParseFromRequest(c.Request, extractor, hmacKeyFunc, jwtRequest.WithClaims(&claims))

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{
					"message": "Invalid token",
					"error":   err.Error(),
				})
			return
		}

		if !opts.externalIssuers[claims.Issuer] {
			isTokenWhitelisted, err := isTokenWhitelisted(tokenStore, &claims)

			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError,
					gin.H{
						"message": "Failed to validate user token",
						"error":   err.Error(),
					})
				log.Println("Failed to lookup user token:", err)
				return
			}

			if !isTokenWhitelisted {
				c.AbortWithStatusJSON(http.StatusUnauthorized,
					gin.H{
						"message": "Token was deleted",
					})
				return
			}
		} else if claims.ExpiresAt == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{
					"message": "Non expiring tokens are not allowed from external issuers",
				})
			return
		} else {
			// basically do nothing, we allow expiring tokens from external issuers
		}

		saveUserIntoContext(c, &claims, &opts)
	}
}

func isTokenWhitelisted(tokenStore TokenStore, claims *ScopedClaims) (bool, error) {
	userID := claims.Subject
	tokenID := claims.Id
	token, err := tokenStore.Lookup(userID, tokenID)
	return token != nil, err
}

func saveUserIntoContext(c *gin.Context, claims *ScopedClaims, opts *options) {
	var toSave interface{}
	toSave = claims
	if opts.claimConverter != nil {
		toSave = opts.claimConverter(claims)
	}
	newContext := context.WithValue(c.Request.Context(), CurrentUser, toSave)
	c.Request = c.Request.WithContext(newContext)
}

// GetCurrentUser tries to get the saved user from Context
func GetCurrentUser(c *gin.Context) interface{} {
	return c.Request.Context().Value(CurrentUser)
}
