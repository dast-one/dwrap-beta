FROM kalilinux/kali-rolling

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    sqlmap \
&& apt-get clean; rm -rf /var/lib/apt/lists/*
