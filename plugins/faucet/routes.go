package faucet

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gobuffalo/packr/v2"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/pkg/errors"
	"golang.org/x/time/rate"

	"github.com/gohornet/hornet/pkg/restapi"
)

var (
	// holds faucet website assets
	appBox = packr.New("Faucet_App", "./frontend/public")
)

const (

	// RouteFaucetInfo is the route to give info about the faucet address.
	// GET returns address, balance, bech32HRP and tokenName of the faucet.
	RouteFaucetInfo = "/info"

	// RouteFaucetEnqueue is the route to tell the faucet to pay out some funds to the given address.
	// POST enqueues a new request.
	RouteFaucetEnqueue = "/enqueue"
)

func appBoxMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			contentType := calculateMimeType(c)

			path := strings.TrimPrefix(c.Request().URL.Path, "/")
			if len(path) == 0 {
				path = "index.html"
				contentType = echo.MIMETextHTMLCharsetUTF8
			}
			staticBlob, err := appBox.Find(path)
			if err != nil {
				// If the asset cannot be found, fall back to the index.html for routing
				path = "index.html"
				contentType = echo.MIMETextHTMLCharsetUTF8
				staticBlob, err = appBox.Find(path)
				if err != nil {
					return next(c)
				}
			}
			return c.Blob(http.StatusOK, contentType, staticBlob)
		}
	}
}

func calculateMimeType(e echo.Context) string {
	url := e.Request().URL.String()

	switch {
	case strings.HasSuffix(url, ".html"):
		return echo.MIMETextHTMLCharsetUTF8
	case strings.HasSuffix(url, ".css"):
		return "text/css"
	case strings.HasSuffix(url, ".js"):
		return echo.MIMEApplicationJavaScript
	case strings.HasSuffix(url, ".json"):
		return echo.MIMEApplicationJSONCharsetUTF8
	case strings.HasSuffix(url, ".png"):
		return "image/png"
	case strings.HasSuffix(url, ".svg"):
		return "image/svg+xml"
	default:
		return echo.MIMETextHTMLCharsetUTF8
	}
}

func enforceMaxOneDotPerURL(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if strings.Count(c.Request().URL.Path, "..") != 0 {
			return c.String(http.StatusForbidden, "path not allowed")
		}
		return next(c)
	}
}

func setupRoutes(e *echo.Echo) {

	e.Pre(enforceMaxOneDotPerURL)
	//e.Use(middleware.CSRF())

	e.Group("/*").Use(appBoxMiddleware())

	// Pass all the requests through to the local rest API
	apiGroup := e.Group("/api")

	allowedRoutes := map[string][]string{
		http.MethodGet: {
			"/api/info",
		},
	}

	rateLimiterSkipper := func(context echo.Context) bool {
		// Check for which route we will skip the rate limiter
		routesForMethod, exists := allowedRoutes[context.Request().Method]
		if !exists {
			return false
		}

		path := context.Request().URL.EscapedPath()
		for _, prefix := range routesForMethod {
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}

		return false
	}

	rateLimiterConfig := middleware.RateLimiterConfig{
		Skipper: rateLimiterSkipper,
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(
			middleware.RateLimiterMemoryStoreConfig{
				Rate:      rate.Limit(1 / 300.0), // 1 request every 5 minutes
				Burst:     10,                    // additional burst of 10 requests
				ExpiresIn: 5 * time.Minute,
			},
		),
		IdentifierExtractor: func(ctx echo.Context) (string, error) {
			id := ctx.RealIP()
			return id, nil
		},
		ErrorHandler: func(context echo.Context, err error) error {
			return context.JSON(http.StatusForbidden, nil)
		},
		DenyHandler: func(context echo.Context, identifier string, err error) error {
			return context.JSON(http.StatusTooManyRequests, nil)
		},
	}
	apiGroup.Use(middleware.RateLimiterWithConfig(rateLimiterConfig))

	apiGroup.GET(RouteFaucetInfo, func(c echo.Context) error {
		resp, err := getFaucetInfo(c)
		if err != nil {
			return err
		}

		return restapi.JSONResponse(c, http.StatusOK, resp)
	})

	apiGroup.POST(RouteFaucetEnqueue, func(c echo.Context) error {
		resp, err := addFaucetOutputToQueue(c)
		if err != nil {
			// own error handler to have nicer user facing error messages.
			var statusCode int
			var message string

			var e *echo.HTTPError
			if errors.As(err, &e) {
				statusCode = e.Code
				if errors.Is(err, restapi.ErrInvalidParameter) {
					message = strings.Replace(err.Error(), ": "+errors.Unwrap(err).Error(), "", 1)
				} else {
					message = err.Error()
				}
			} else {
				statusCode = http.StatusInternalServerError
				message = fmt.Sprintf("internal server error. error: %s", err.Error())
			}

			return c.JSON(statusCode, restapi.HTTPErrorResponseEnvelope{Error: restapi.HTTPErrorResponse{Code: strconv.Itoa(statusCode), Message: message}})
		}

		return restapi.JSONResponse(c, http.StatusAccepted, resp)
	})
}
