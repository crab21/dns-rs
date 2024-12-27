FROM rust:1.83-bullseye
RUN  apt-get update && apt-get install -y musl-tools libssl-dev pkg-config && rustup target add x86_64-unknown-linux-musl
WORKDIR /app
COPY init.sh init.sh
RUN chmod +x init.sh
CMD ["sh", "init.sh"]