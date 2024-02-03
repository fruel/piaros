ARG BUILDER_TAG
FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/rust-musl-cross:${BUILDER_TAG} as builder

ADD https://github.com/upx/upx/releases/download/v4.2.2/upx-4.2.2-amd64_linux.tar.xz /upx.tar.xz
RUN tar -xf /upx.tar.xz -C /bin/ --strip-components=1 upx-4.2.2-amd64_linux/upx

COPY . /home/rust/src

RUN cargo build --release && \
    upx --best --lzma target/*/release/piaros

FROM scratch
COPY --from=builder /home/rust/src/target/*/release/piaros /
ENTRYPOINT [ "/piaros" ]
