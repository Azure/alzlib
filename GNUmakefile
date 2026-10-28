TEST?=$$(go list ./... |grep -v 'vendor')
# Several packages call Azure; run them one at a time so that concurrent CI jobs sharing a tenant
# do not exceed the Azure Resource Manager read limits.
TESTFLAGS?=-p 1

.PHONY: lint
lint:
	golangci-lint run

.PHONY: testrace
testrace:
	go test $(TESTFLAGS) -test.v -race $(TEST)

.PHONY: test
test:
	go test $(TESTFLAGS) -test.v $(TEST)

# Create a test coverage report and launch a browser to view it
.PHONY: testcover
testcover:
	if [ -f "coverage.out" ]; then rm coverage.out; fi
	go test $(TESTFLAGS) -v -coverprofile=coverage.out -covermode=count $(TEST)

.PHONY: tool
tool:
	go install ./cmd/alzlibtool
