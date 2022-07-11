package firewall

import (
	"strings"

	"github.com/giantswarm/microerror"
)

var failedParseSubnetError = &microerror.Error{
	Kind: "failedParseSubnet",
	Desc: "parsing of a subnet failed",
}

func isAlreadyExistError(err error) bool {
	return strings.Contains(err.Error(), "already exists")
}

func isNotFoundError(err error) bool {
	return strings.Contains(err.Error(), "404")
}
