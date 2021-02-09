FROM golang:1.14

ARG ADDR
ARG PORT
ARG RLOG_LOG_LEVEL

WORKDIR /app

COPY main.go \
  types.go \
  debian.go \
  /app/

RUN go build -o app .

EXPOSE ${PORT}

CMD "/app/app"
