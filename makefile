update-nuts-deps:
	cat go.mod | awk '/nuts-foundation.* / {print $$1 "@master"}' | xargs go get

test:
	go test ./...

update-docs:
	go run ./docs
	./generate_readme.sh
