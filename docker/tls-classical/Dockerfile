ARG TLS_CLASSICAL_IMAGE=nginx:1.27-alpine
FROM ${TLS_CLASSICAL_IMAGE}

RUN apk add --no-cache openssl bash gettext

COPY entrypoint.sh /entrypoint.sh
COPY nginx.conf.template /etc/nginx/nginx.conf.template
RUN chmod +x /entrypoint.sh

EXPOSE 8443
ENTRYPOINT ["/entrypoint.sh"]