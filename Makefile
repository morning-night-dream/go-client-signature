include .env
export

.PHONY: aqua
aqua: # export PATH="${AQUA_ROOT_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/aquaproj-aqua}/bin:$PATH"
	@go run github.com/aquaproj/aqua-installer@latest

.PHONY: tool
tool:
	@aqua i

.PHONY: mod
mod:
	@go mod tidy

.PHONY: gen
gen:
	@oapi-codegen -generate types -package api ./api/openapi.yaml > ./api/types.gen.go
	@oapi-codegen -generate chi-server -package api ./api/openapi.yaml > ./api/server.gen.go
	@oapi-codegen -generate client -package api ./api/openapi.yaml > ./api/client.gen.go
	@go mod tidy

.PHONY: server
server:
	@go run cmd/server/main.go

.PHONY: client
client:
	@go run cmd/client/main.go
