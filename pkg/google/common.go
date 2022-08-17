package google

import (
	"errors"
	"strings"

	"google.golang.org/api/googleapi"
)

func HasHttpCode(err error, statusCode int) bool {
	var googleErr *googleapi.Error
	if errors.As(err, &googleErr) {
		if googleErr.Code == statusCode {
			return true
		}
	}

	return false
}

func GetResourceName(selfLink *string) string {
	if selfLink == nil {
		return ""
	}

	s := *selfLink
	return s[strings.LastIndex(s, "/")+1:]
}
