FROM php:8.3-cli
RUN apt-get update -qq && apt-get install -y -qq libgmp-dev unzip && docker-php-ext-install gmp
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
WORKDIR /app
COPY composer.json phpunit.xml ./
RUN composer install -q
COPY src/ src/
COPY tests/ tests/
CMD ["vendor/bin/phpunit", "--colors=always"]
