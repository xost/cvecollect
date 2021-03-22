include .env

#PRJNAME=$(shell basename "$(PWD)")

STDERR=.$(PRJNAME)-stderr.txt
STDOUT=.$(PRJNAME)-stdout.txt

build:
	go build -ldflags="-s -w"

debug:
	go build

lint:
	go vet .
	golint .

run:
	docker-compose up --build -d

down:
	docker-compose down

logs:
	docker logs --follow cvecollect_app_1

tests:
	docker run -d -p 6379:6379 --name rejson redislabs/rejson:latest 
	PORT=$(PORT) RLOG_LOG_LEVEL=INFO go test -race -v -coverprofile=cover.out || docker stop rejson && docker rm rejson

cover:
	@PORT=$(PORT) go test -coverprofile=cover.out -v && go tool cover -html=cover.out && unlink cover.out
