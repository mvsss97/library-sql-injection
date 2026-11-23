FROM php:8.2-apache-bookworm

ARG WWW_DIR=/var/www/SQL_Injection

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && docker-php-ext-install mysqli

COPY Code ${WWW_DIR}
COPY apache_sql_injection.conf /etc/apache2/sites-available/000-sql-injection.conf
COPY seed-lab.ini /usr/local/etc/php/conf.d/seed-lab.ini

RUN a2dissite 000-default.conf \
    && a2ensite 000-sql-injection.conf \
    && chown -R root:root ${WWW_DIR} \
    && find ${WWW_DIR} -type d -exec chmod 0755 {} + \
    && find ${WWW_DIR} -type f -exec chmod 0644 {} +
