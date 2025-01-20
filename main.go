package main

import (
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/livekit/protocol/auth"
)

func main() {

	// Initialize Echo
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:8080", "https://*.traq-preview.trapti.tech"},
		AllowMethods: []string{http.MethodGet, http.MethodPost},
	}))

	// Routes
	e.GET("/token", generateToken)

	// Start server
	e.Logger.Fatal(e.Start(":8080"))
}

func generateToken(c echo.Context) error {
	// Get user ID from X-Forwarded-User header
	userID := c.Request().Header.Get("X-Forwarded-User")
	if userID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "X-Forwarded-User header is required",
		})
	}

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
