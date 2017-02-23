NAME := dcos-services
REVISION := $(shell git describe --tags --always --dirty="-dev")

LDFLAGS := -X github.com/dcos/dcos-oauth/version.REVISION=$(REVISION)

PKG_LIST := common dcos-oauth security security/ldap test/integration
TEST_LIST = $(foreach int, $(PKG_LIST), github.com/dcos/dcos-oauth/$(int))

install:
	go install -v -tags '$(TAGS)' -ldflags '$(LDFLAGS)' ./...

save:
	godep save ./...

docker:
	id
	sudo docker build -t $(NAME) .

test: docker
	go test $(TEST_LIST)

unittest:
	go test ./dcos-oauth ./security/...

fulltest:
	fulltest.sh

.PHONY: install save docker test unittest fulltest

DIRS=$(subst $(space),$(newline),$(shell go list ./... | grep -v /vendor/))
TEST=$(subst $(space),$(newline),$(shell go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.Dir}}{{end}}' ./...))
NOTEST=$(filter-out $(TEST),$(DIRS))

test-compile: $(addsuffix .test-compile, $(TEST))

%.test-compile:
	cd $* && go test -p 1 -v -c .
