package firewall

import (
	"strings"
)

func isAlreadyExistError(err error) bool {
	return strings.Contains(err.Error(), "already exists")
}

func isNotFoundError(err error) bool {
	return strings.Contains(err.Error(), "404")
}
