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

func GetResourceName(selfLink string) string {
	return selfLink[strings.LastIndex(selfLink, "/")+1:]
}

func IsNilOrEmpty(value *string) bool {
	return value == nil || *value == ""
}
