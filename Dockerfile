FROM alpine

COPY . /src/github.com/taliesins/traefik-plugin-oidc

CMD cp -R /src /plugins-local/