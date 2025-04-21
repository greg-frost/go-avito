FROM golang:1.20 as build

COPY . /src

WORKDIR /src

RUN CGO_ENABLED=0 GOOS=linux go build -o avito_api cmd/api/main.go

FROM scratch

COPY --from=build /src/avito_api .

EXPOSE 8080

CMD ["/avito_api"]