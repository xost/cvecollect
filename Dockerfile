FROM golang:1.14

ARG ADDR
ARG PORT
ARG RLOG_LOG_LEVEL

WORKDIR /app

COPY go.mod \
  go.sum \
  main.go \
  types.go \
  debian.go \
  redhat.go \
  ubuntu.go \
  util.go \
  /app/

RUN go mod download
RUN go build -o app .

EXPOSE ${PORT}

CMD "/app/app"
