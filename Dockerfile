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


COPY . /root/volepsi
WORKDIR /root/volepsi
# Increase --par if you want to speed up the build process
RUN python3 build.py --par=1 -DVOLE_PSI_ENABLE_BOOST=ON