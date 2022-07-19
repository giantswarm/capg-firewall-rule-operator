package matchers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/googleapis/gax-go/v2/apierror"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
	"google.golang.org/api/googleapi"
)

type beGoogleAPIErrorWithStatusMatcher struct {
	expected int
}

func BeGoogleAPIErrorWithStatus(expected int) types.GomegaMatcher {
	return &beGoogleAPIErrorWithStatusMatcher{expected: expected}
}

func (m *beGoogleAPIErrorWithStatusMatcher) Match(actual interface{}) (bool, error) {
	if actual == nil {
		return false, nil
	}

	actualError, isError := actual.(error)
	if !isError {
		return false, fmt.Errorf("%#v is not an error", actual)
	}

	var apiErr *apierror.APIError
	isAPIError := errors.As(actualError, &apiErr)
	if isAPIError {
		actualError = apiErr.Unwrap()
	}

	matches, err := BeAssignableToTypeOf(actualError).Match(&googleapi.Error{})
	if err != nil || !matches {
		return false, err
	}

	googleAPIError, isGoogleAPIError := actualError.(*googleapi.Error)
	if !isGoogleAPIError {
		return false, nil
	}
	return Equal(googleAPIError.Code).Match(m.expected)
}

func (m *beGoogleAPIErrorWithStatusMatcher) FailureMessage(actual interface{}) (message string) {
	return format.Message(
		actual,
		fmt.Sprintf("to be a google api error with status code: %s", m.getExpectedStatusText()),
	)
}

func (m *beGoogleAPIErrorWithStatusMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return format.Message(
		actual,
		fmt.Sprintf("to not be a google api error with status: %s", m.getExpectedStatusText()),
	)
}

func (m *beGoogleAPIErrorWithStatusMatcher) getExpectedStatusText() string {
	return fmt.Sprintf("%d %s", m.expected, http.StatusText(m.expected))
}
