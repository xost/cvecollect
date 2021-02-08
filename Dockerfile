FROM golang:1.14

WORKDIR /app

COPY go.mod \
  go.sum \
  main.go \
  types.go \
  cvemonitor_test.go \
  debian.go \
  ./

RUN go mod download

#COPY . .

RUN go build -o app .

EXPOSE 8080

CMD ./app
