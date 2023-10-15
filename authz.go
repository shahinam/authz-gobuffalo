package authz

import (
	"maps"
	"net/http"
	"strings"

	casbin "github.com/casbin/casbin/v2"
	"github.com/gobuffalo/buffalo"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

var actionAliases = map[string]string{
	"new":     "create",
	"edit":    "update",
	"destroy": "delete",
}

type Authorize struct {
	Enforcer      *casbin.Enforcer
	RoleFunc      func(buffalo.Context) (string, error)
	ActionAliases map[string]string
	DeniedCode    int
	DeniedMessage string
}

func (r Authorize) Middleware() buffalo.MiddlewareFunc {
	if r.DeniedCode == 0 {
		r.DeniedCode = http.StatusForbidden
	}

	if r.DeniedMessage == "" {
		r.DeniedMessage = "You are unauthorized to perform the requested action"
	}

	// Merge and overwrite exiting aliases.
	maps.Copy(actionAliases, r.ActionAliases)

	return func(next buffalo.Handler) buffalo.Handler {
		return func(c buffalo.Context) error {
			role, err := r.RoleFunc(c)
			if err != nil {
				return errors.WithStack(err)
			}

			var resource, action string
			ri := mux.CurrentRoute(c.Request()).GetHandler().(*buffalo.RouteInfo)

			// Get the resource from Resource when available.
			if ri.ResourceName != "" {
				resource = strings.ToLower(strings.Split(ri.ResourceName, "Resource")[0])
			}

			handler := strings.Split(ri.HandlerName, "/actions.")
			action = strings.ToLower(handler[len(handler)-1])

			// Get action.
			// If action is non-resource, then use first part as resource and 2nd part as action.
			if strings.Contains(action, ".") {
				handler = strings.Split(action, ".")

				// if this is not a resource
				if resource == "" {
					resource = handler[0]
				}

				// if action has an alias, use that.
				action = handler[1]
				if n := actionAliases[action]; n != "" {
					action = n
				}
			}

			res, err := r.Enforcer.Enforce(role, resource, action)
			if err != nil {
				return errors.WithStack(err)
			}

			if res {
				return next(c)
			}

			return c.Error(int(r.DeniedCode), errors.New(string(r.DeniedMessage)))
		}
	}
}
