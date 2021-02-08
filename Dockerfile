FROM golang:1.14

ARG ADDR
ARG PORT
ARG LOGLEVEL

WORKDIR /app

COPY main.go \
  types.go \
  debian.go \
  /app/

RUN go build -o app .

CMD "/app/app"
