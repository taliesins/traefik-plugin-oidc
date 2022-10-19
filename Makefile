.PHONY: lint test vendor clean

export GO111MODULE=on

default: lint test

install_build_tools:
	go install github.com/traefik/yaegi/cmd/yaegi@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

lint:
	golangci-lint run

test:
	go test -v -cover ./...

yaegi_test:
	yaegi test -v .

vendor:
	go mod vendor

clean:
	rm -rf ./vendor

docker_build:
	docker build . -t traefik-plugin-oidc:latest

k8s:
	helm repo add traefik https://helm.traefik.io/traefik
	helm repo add cowboysysop https://cowboysysop.github.io/charts/
	helm install -f traefik-values.yaml traefik traefik/traefik
	helm install -f whoami-values.yaml whoami cowboysysop/whoami
