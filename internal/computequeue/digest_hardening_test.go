package computequeue

import (
	"reflect"
	"testing"
)

func TestRawReceiptAndUnsafeDigestHelpersAreNotExported(t *testing.T) {
	testCases := []struct {
		value  any
		method string
	}{
		{AttemptTransition{}, "ValidateAgainst"},
		{AssignmentPlan{}, "MakeDigest"},
		{AssignmentAuthorization{}, "ReceiptSubjectDigest"},
		{AssignmentRecord{}, "ReceiptSubjectDigest"},
	}
	for _, testCase := range testCases {
		if _, present := reflect.TypeOf(testCase.value).MethodByName(testCase.method); present {
			t.Errorf("unsafe helper remains exported: %T.%s", testCase.value, testCase.method)
		}
	}
}

func TestMalformedExecutorDigestHelpersDoNotPanic(t *testing.T) {
	testCases := map[string]ExecutorBinding{
		"missing source-local binding": {Kind: ExecutorSourceLocal},
		"missing worker binding":       {Kind: ExecutorWorker},
		"unknown executor kind":        {Kind: ExecutorKind("unknown")},
	}
	for name, executor := range testCases {
		t.Run(name, func(t *testing.T) {
			if err := executor.Validate(); err == nil {
				t.Fatal("malformed executor unexpectedly validated")
			}

			authorization := AssignmentAuthorization{Executor: executor}
			assignment := AssignmentRecord{Executor: executor}
			receipt := ReceiptRecord{}
			assertDoesNotPanic(t, "assignment plan digest", func() {
				_ = (AssignmentPlan{Assignments: []AssignmentAuthorization{authorization}}).makeDigest()
			})
			assertDoesNotPanic(t, "authorization receipt digest", func() {
				_ = authorization.receiptSubjectDigest("", "", receipt)
			})
			assertDoesNotPanic(t, "assignment receipt digest", func() {
				_ = assignment.receiptSubjectDigest(receipt)
			})
		})
	}
}

func assertDoesNotPanic(t *testing.T, operation string, body func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("%s panicked: %v", operation, recovered)
		}
	}()
	body()
}
