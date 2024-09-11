SHELL=/bin/bash -o pipefail
GO ?= go

NAME := keycloak
OUTPUT := lib$(NAME).so
KEYCLOAK_SPI_LOCATION := ../../kc-falco/hack/

ifeq ($(DEBUG), 1)
    GODEBUGFLAGS= GODEBUG=cgocheck=2
else
    GODEBUGFLAGS= GODEBUG=cgocheck=0
endif

all: build

clean:
	@rm -f $(OUTPUT)

cp-keycloak: build
	cp $(OUTPUT) $(KEYCLOAK_SPI_LOCATION)/$(OUTPUT)
	cp rules/*.yaml $(KEYCLOAK_SPI_LOCATION)

build: clean
	@$(GODEBUGFLAGS) $(GO) build -buildmode=c-shared -buildvcs=false -o $(OUTPUT) ./plugin