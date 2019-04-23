package ginauth0

import (
	"net/http"

	auth0 "github.com/auth0-community/go-auth0"
	"github.com/gin-gonic/gin"
	jose "gopkg.in/square/go-jose.v2"
)

//Auth struct with Identitykey, client jwk, and jwtValidatior
type Auth struct {
	IdentityKey string
	Client      *auth0.JWKClient
	Validator   *auth0.JWTValidator
}

//New init Auth using for handle request in middleware
func New(identityKey string, options auth0.JWKClientOptions, audience []string, issuer string, method jose.SignatureAlgorithm) *Auth {
	authClient := auth0.NewJWKClient(options, nil)
	configuration := auth0.NewConfiguration(authClient, audience, issuer, method)
	validator := auth0.NewValidator(configuration, nil)
	if identityKey == "" {
		identityKey = "identity"
	}
	return &Auth{
		IdentityKey: identityKey,
		Client:      authClient,
		Validator:   validator,
	}
}

//MiddlewareFunc validate request and store claims into context with identityKey
func (auth *Auth) MiddlewareFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := auth.Validator.ValidateRequest(c.Request)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		claims := map[string]interface{}{}
		err = auth.Validator.Claims(c.Request, token, &claims)
		if err != nil {
			c.AbortWithStatus(http.StatusForbidden)
		}
		c.Set(auth.IdentityKey, &claims)
		c.Next()
	}
}
