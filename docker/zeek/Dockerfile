ARG ZEEK_IMAGE=zeek/zeek:6.2
FROM ${ZEEK_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends inotify-tools \
  && rm -rf /var/lib/apt/lists/*
COPY watch_and_process.sh /watch_and_process.sh
RUN chmod +x /watch_and_process.sh
ENTRYPOINT ["/watch_and_process.sh"]