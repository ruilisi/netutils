FROM golang:1.25
WORKDIR /app
ENV CGO_ENABLED=1
RUN apt-get update && apt-get install -y build-essential
