SHELL=/bin/bash -o pipefail
GO ?= go

NAME := keycloak
OUTPUT := lib$(NAME).so
KEYCLOAK_SPI_LOCATION := ../../kc-falco/hack/

ifeq ($(DEBUG), 1)
    GODEBUGFLAGS= GODEBUG=cgocheck=1
else
    GODEBUGFLAGS= GODEBUG=cgocheck=0
endif

all: $(OUTPUT)

clean:
	@rm -f $(OUTPUT)

cp-keycloak: $(OUTPUT)
	cp $(OUTPUT) $(KEYCLOAK_SPI_LOCATION)/$(OUTPUT)
	cp rules/*.yaml $(KEYCLOAK_SPI_LOCATION)

$(OUTPUT):
	@$(GODEBUGFLAGS) $(GO) build -buildmode=c-shared -o $(OUTPUT) ./plugin