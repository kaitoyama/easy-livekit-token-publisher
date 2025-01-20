package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/livekit/protocol/auth"
	"gopkg.in/square/go-jose.v2/jwt"
)

const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErNkbjzyMz81Np8sBb8Jr3bUOkLW4
H41Ugac0eSzPyemDvmaCIDpRofi3Rb0EgaSRSqC3IoBgVmQ+bPLtueUtUg==
-----END PUBLIC KEY-----`

const devPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsif3xPZ/ObY12BCB2SfC3045eSkq
G9Kw2nD2DYgoJHFCPTzCLUqOKDpig4H0tYXH4RaSy6+apfgfeE/TJagHuw==
-----END PUBLIC KEY-----`

func main() {

	// Initialize Echo
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:8080", "https://*.traq-preview.trapti.tech"},
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodOptions},
	}))

	// Routes
	e.GET("/token", generateToken)

	// Start server
	e.Logger.Fatal(e.Start(":8080"))
}

func generateToken(c echo.Context) error {
	// Get and verify JWT
	authHeader := c.Request().Header.Get("Authorization")
	if authHeader == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Authorization header is required",
		})
	}

	// Parse and verify JWT
	tokenString := authHeader[len("Bearer "):]
	parsedToken, err := jwt.ParseSigned(tokenString)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Invalid token",
		})
	}

	// Verify algorithm is ES256
	if len(parsedToken.Headers) == 0 || parsedToken.Headers[0].Algorithm != "ES256" {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Invalid token algorithm",
		})
	}

	// Try primary public key first
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to parse public key",
		})
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to parse public key",
		})
	}

	ecdsaPubKey := pubKey.(*ecdsa.PublicKey)

	var claims map[string]interface{}
	err = parsedToken.Claims(ecdsaPubKey, &claims)
	if err != nil {
		// If primary key fails, try dev key
		block, _ = pem.Decode([]byte(devPublicKeyPEM))
		if block == nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to parse dev public key",
			})
		}

		pubKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to parse dev public key",
			})
		}

		ecdsaPubKey = pubKey.(*ecdsa.PublicKey)
		if err := parsedToken.Claims(ecdsaPubKey, &claims); err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Invalid token claims",
			})
		}
	}

	// Check token expiration
	exp, ok := claims["exp"].(float64)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Token missing expiration",
		})
	}
	if time.Unix(int64(exp), 0).Before(time.Now()) {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Token has expired",
		})
	}

	name, ok := claims["name"].(string)
	if !ok || name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "name claim is required in JWT",
		})
	}

	userID := name

	// Get API key and secret from environment variables
	apiKey := os.Getenv("LIVEKIT_API_KEY")
	apiSecret := os.Getenv("LIVEKIT_API_SECRET")
	if apiKey == "" || apiSecret == "" {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "API key and secret must be set in environment variables",
		})
	}

	// Create token
	at := auth.NewAccessToken(apiKey, apiSecret)
	grant := &auth.VideoGrant{
		RoomJoin: true,
		Room:     "my-room",
	}
	at.SetVideoGrant(grant).
		SetIdentity(userID).
		SetName(userID).
		SetValidFor(24 * time.Hour)

	token, err := at.ToJWT()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to generate token",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"token": token,
	})
}
