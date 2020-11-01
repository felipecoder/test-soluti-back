#!/bin/bash

php ../vendor/bin/openapi --bootstrap ./swagger-variables.php --output ../public ./swagger-v1.php ../app/Http/Controllers
