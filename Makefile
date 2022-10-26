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
	docker build . -t taliesins/traefik-plugin-oidc:latest

k8s:
	helm repo add traefik https://helm.traefik.io/traefik
	helm repo add cowboysysop https://cowboysysop.github.io/charts/
	helm repo add bitnami https://charts.bitnami.com/bitnami
	helm dependency update charts/traefik-plugin-oidc-example
	helm upgrade --install example charts/traefik-plugin-oidc-example -n example --create-namespace

k8s_uninstall:
	helm uninstall example -n example

k8s_remove:
	helm uninstall example -n example

