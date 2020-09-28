# build relevant binaries from source
FROM golang:1 AS build-go
WORKDIR /src
ADD . /src/
RUN go install ./cmd/certspotter

# also build our custom script for after a match is found
WORKDIR /src/cmd/certreporter
RUN go install .

# pack into minimal image
FROM gcr.io/distroless/base
COPY --from=build-go /go/bin/certspotter /bin/
COPY --from=build-go /go/bin/certreporter /bin/
CMD ["/bin/certspotter"]
