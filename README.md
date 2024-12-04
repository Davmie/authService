# Часть сервиса аутентификации

## Два REST маршрута:
* ```localhost:8080/getTokens``` Выдает пару Access, Refresh токенов для пользователя с идентификатором (GUID) указанным в параметре запроса.
* ```localhost:8080/refreshTokens``` Выполняет Refresh операцию на пару Access, Refresh токенов, указанных в параметрах запроса ```access_token``` и ```refresh_token```.

## Запуск
```docker compose up -d``` из корня проекта