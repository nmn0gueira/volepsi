FROM ubuntu:latest

RUN apt-get update && apt install -y \
	automake \
	autoconf \
	libtool \
	software-properties-common \
	cmake \
	git \
	gdb \
	build-essential \
	libssl-dev \
	python3 \
	&& rm -rf /var/lib/apt/list/*


# Have git use LF line endings if it is not already
RUN git config --global core.autocrlf false
RUN git config --global core.eol lf