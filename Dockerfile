FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795
RUN apk add --no-cache \
      php-8.2 php-8.2-gmp php-8.2-phar php-8.2-openssl php-8.2-mbstring \
      php-8.2-dom php-8.2-xml php-8.2-xmlwriter php-8.2-ctype composer \
  && rm -rf /var/cache/apk/*

USER nonroot
WORKDIR /home/nonroot
COPY --chown=nonroot:nonroot composer.json phpunit.xml ./
RUN composer install -q --no-interaction
COPY --chown=nonroot:nonroot src/ src/
COPY --chown=nonroot:nonroot tests/ tests/
CMD ["vendor/bin/phpunit", "--colors=always"]
