package cidr

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

func ParseFromCommaSeparated(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}

	ipRanges := strings.Split(value, ",")
	for _, cidr := range ipRanges {
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			message := fmt.Sprintf("value: %q contains invalid CIDRs", value)
			return nil, errors.New(message)
		}
	}
	return ipRanges, nil
}
