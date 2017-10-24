#!/usr/bin/make -f

SHELL=/bin/sh
bin=bin
name=notify

all: build

build:
	go build -v -ldflags "-s -w " -o bin/$(name)

clean:
	go clean -x

remove:
	go clean -i
