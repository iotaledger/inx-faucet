package faucet

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"

	"github.com/iotaledger/hive.go/ierrors"
	"github.com/iotaledger/inx-app/pkg/httpserver"
)

const (
	// RouteFaucetHealth is the route to get the health info of the faucet.
	RouteFaucetHealth = "/health"

	// RouteFaucetInfo is the route to give info about the faucet address.
	// GET returns address, balance, bech32Hrp and tokenName of the faucet.
	RouteFaucetInfo = "/info"

	// RouteFaucetEnqueue is the route to tell the faucet to pay out some funds to the given address.
	// POST enqueues a new request.
	RouteFaucetEnqueue = "/enqueue"
)

func enforceMaxOneDotPerURL(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if strings.Count(c.Request().RequestURI, "..") != 0 {
			return c.String(http.StatusForbidden, "path not allowed")
		}

		return next(c)
	}
}

func setupRoutes(e *echo.Echo) {

	e.Pre(enforceMaxOneDotPerURL)

	e.Group("/*").Use(frontendMiddleware())

	e.GET(RouteFaucetHealth, func(c echo.Context) error {
		if !deps.NodeBridge.NodeStatus().IsHealthy {
			return c.NoContent(http.StatusServiceUnavailable)
		}

		return c.NoContent(http.StatusOK)
	})

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

	if ParamsFaucet.RateLimit.Enabled {
		rateLimiterConfig := middleware.RateLimiterConfig{
			Skipper: rateLimiterSkipper,
			Store: middleware.NewRateLimiterMemoryStoreWithConfig(
				middleware.RateLimiterMemoryStoreConfig{
					Rate:      rate.Limit(float64(ParamsFaucet.RateLimit.MaxRequests) / ParamsFaucet.RateLimit.Period.Seconds()),
					Burst:     ParamsFaucet.RateLimit.MaxBurst,
					ExpiresIn: 5 * time.Minute,
				},
			),
			IdentifierExtractor: func(ctx echo.Context) (string, error) {
				id := ctx.RealIP()

				return id, nil
			},
		}
		apiGroup.Use(middleware.RateLimiterWithConfig(rateLimiterConfig))
	}

	apiGroup.GET(RouteFaucetInfo, func(c echo.Context) error {
		resp, err := getFaucetInfo(c)
		if err != nil {
			return err
		}

		return httpserver.JSONResponse(c, http.StatusOK, resp)
	})

	apiGroup.POST(RouteFaucetEnqueue, func(c echo.Context) error {
		resp, err := addFaucetOutputToQueue(c)
		if err != nil {
			// own error handler to have nicer user facing error messages.
			var statusCode int
			var message string

			var e *echo.HTTPError
			if ierrors.As(err, &e) {
				statusCode = e.Code
				if ierrors.Is(err, httpserver.ErrInvalidParameter) {
					message = strings.Replace(err.Error(), ": "+ierrors.Unwrap(err).Error(), "", 1)
				} else {
					message = err.Error()
				}
			} else {
				statusCode = http.StatusInternalServerError
				message = fmt.Sprintf("internal server error. error: %s", err.Error())
			}

			return c.JSON(statusCode, httpserver.HTTPErrorResponseEnvelope{Error: httpserver.HTTPErrorResponse{Code: strconv.Itoa(statusCode), Message: message}})
		}

		return httpserver.JSONResponse(c, http.StatusAccepted, resp)
	})
}
