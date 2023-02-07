NAME=signal-strength

all: build

deps:
	go mod tidy

build:
	go build -o ${NAME} main.go

clean:
	go clean
	rm ${NAME}