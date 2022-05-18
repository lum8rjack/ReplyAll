NAME := ReplyAll
BUILD := go build -trimpath -ldflags

default: linux

clean:
	rm -f $(NAME)*.bin
	rm -f $(NAME)*.exe

linux:
	echo "Compiling for Linux x64"
	GOOS=linux GOARCH=amd64 $(BUILD) "-s -w" -o $(NAME).bin

linux-static:
	echo "Compiling static binary for Linux x64"
	GOOS=linux GOARCH=amd64 $(BUILD) "-s -w -linkmode external -extldflags=-static" -o $(NAME).bin

mac:
	echo "Compiling for Mac x64"
	GOOS=darwin GOARCH=amd64 $(BUILD) "-s -w" -o $(NAME)-Darwin64.bin

m1:
	echo "Compiling for Mac M1"
	GOOS=darwin GOARCH=arm64 $(BUILD) "-s -w" -o $(NAME)-M1.bin

arm:
	echo "Compiling for Linux Arm64"
	GOOS=linux GOARCH=arm64 $(BUILD) "-s -w" -o $(NAME)-LinuxArm64.bin

windows:
	echo "Compiling for Windows x64"
	GOOS=windows GOARCH=amd64 $(BUILD) "-s -w" -o $(NAME)-Windows64.exe

