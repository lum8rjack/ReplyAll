NAME := ReplyAll
BUILD := go build -trimpath -ldflags

default: linux

clean:
	rm -f $(NAME)*.bin

linux:
	echo "Compiling for Linux x64"
	GOOS=linux GOARCH=amd64 $(BUILD) "-s -w" -o $(NAME).bin

linux-static:
	echo "Compiling for Linux x64"
	GOOS=linux GOARCH=amd64 $(BUILD) "-s -w -linkmode external -extldflags=-static" -o $(NAME).bin
