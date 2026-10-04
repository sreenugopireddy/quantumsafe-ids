FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY capture.sh /capture.sh
RUN chmod +x /capture.sh
ENTRYPOINT ["/capture.sh"]