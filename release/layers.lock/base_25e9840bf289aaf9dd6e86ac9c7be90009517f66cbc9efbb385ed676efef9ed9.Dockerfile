FROM debian:buster
RUN apt-get update -y && apt-get install --no-install-recommends -y -q \
                         curl \
                         zip \
                         build-essential \
                         gcc-multilib \
                         g++-multilib \
                         ca-certificates \
                         git mercurial bzr \
                         gnupg \
                         libltdl-dev \
                         libltdl7 \
						             bash
RUN curl -sL https://deb.nodesource.com/setup_10.x | bash -
RUN curl -sL https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
RUN echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
RUN apt-get update -y && apt-get install -y -q nodejs yarn=1.19.1-1
RUN rm -rf /var/lib/apt/lists/*

ENV GOPATH /gopath
ENV GOROOT /goroot

RUN mkdir $GOROOT && mkdir $GOPATH

RUN curl https://storage.googleapis.com/golang/go1.12.13.linux-amd64.tar.gz \
           | tar xvzf - -C $GOROOT --strip-components=1

ENV PATH $GOROOT/bin:$GOPATH/bin:$PATH

RUN go get golang.org/x/tools/cmd/goimports
RUN go get github.com/mitchellh/gox
RUN go get github.com/hashicorp/go-bindata
RUN go get github.com/hashicorp/go-bindata/go-bindata
RUN go get github.com/elazarl/go-bindata-assetfs
RUN go get github.com/elazarl/go-bindata-assetfs/go-bindata-assetfs

ENV REPO=github.com/hashicorp/vault
ENV DIR=$GOPATH/src/$REPO

RUN mkdir -p $DIR

WORKDIR $DIR

