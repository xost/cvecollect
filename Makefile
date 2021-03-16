include .env

PRJNAME=$(shell basename "$(PWD)")

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

stop:
	docker-compose down

logs:
	docker logs --follow cvecollect_app_1

tests:
	@PORT=$(PORT) RLOG_LOG_LEVEL=$(RLOG_LOG_LEVEL) go test -race

cover:
	@PORT=$(PORT) go test -coverprofile=cover.out && go tool cover -html=cover.out && unlink cover.out
