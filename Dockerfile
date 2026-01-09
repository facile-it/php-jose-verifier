ARG PHP_VERSION=8.1
FROM php:${PHP_VERSION}-cli-alpine
RUN apk add --no-cache gmp-dev && docker-php-ext-install -j$(nproc) gmp
RUN php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" \
    && php composer-setup.php \
    && php -r "unlink('composer-setup.php');" \
    && mv composer.phar /usr/local/bin/composer
