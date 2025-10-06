FROM golang:1.24-alpine AS build

RUN apk --no-cache add git

RUN mkdir /app
ADD . /app
WORKDIR /app

# remove any go module files and get deps
RUN rm -f go.mod go.sum
RUN go mod init github.com/cliveyg/poptape-admin
RUN go mod tidy

RUN go mod download

# need these flags or alpine image won't run due to dynamically linked libs in binary
RUN CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -a -ldflags '-w' -o admin

FROM alpine:latest

# installing mongo-tools installs a laod of unneeded
# binaries which we then remove
RUN apk add --no-cache bash postgresql-client mongodb-tools && \
    mkdir -p /admin && \
    mkdir -p /admin/log && \
    rm /usr/bin/mongoimport \
       /usr/bin/mongoexport \
       /usr/bin/mongostat \
       /usr/bin/mongofiles \
       /usr/bin/mongotop \
       /usr/bin/bsondump
COPY --from=build /app/admin /admin
COPY --from=build /app/.env /admin
WORKDIR /admin

# Make port available to the world outside this container
EXPOSE $PORT

# Run admin binary when the container launches
CMD ["./admin"]
