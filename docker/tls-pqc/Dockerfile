ARG PQC_BASE_IMAGE=nginx:1.27-alpine
FROM ${PQC_BASE_IMAGE}

COPY entrypoint.sh /entrypoint.sh
COPY nginx.conf.template /etc/nginx/nginx.conf.template

EXPOSE 8444
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]