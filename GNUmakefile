TEST?=$$(go list ./... |grep -v 'vendor')

.PHONY: lint
lint:
	golangci-lint run

.PHONY: testrace
testrace:
	go test -test.v -race $(TEST)

.PHONY: test
test:
	go test -test.v $(TEST)

# Create a test coverage report and launch a browser to view it
.PHONY: testcover
testcover:
	if [ -f "coverage.out" ]; then rm coverage.out; fi
	go test -coverprofile=coverage.out -covermode=count $(TEST)
