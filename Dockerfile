FROM golang:1.21

WORKDIR /

COPY . /app


WORKDIR /app

RUN go mod download
RUN go mod tidy
RUN go build cmd/main.go

EXPOSE 8080

CMD ["./main"]
