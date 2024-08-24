# auth-service-go

Этот проект представляет собой сервис аутентификации, который предоставляет и обновляет токены доступа для пользователей.

## Используемые технологии

- Go: Язык программирования, на котором написан сервис.
- PostgreSQL: База данных для хранения информации о пользователях и хэшированных refresh токенах.
- Docker: Используется для контейнеризации сервиса, что облегчает его развертывание и управление зависимостями.

## Функционал

Сервис предоставляет два REST API:

1) Выдача токенов
   - **Эндпоинт**: `GET /auth/token/{client_id}`
   - **Описание**: выдает пару Access и Refresh токенов для пользователя, идентифицированного по GUID, переданному в запросе.
   - **Пример запроса**: `GET http://localhost:8080/auth/token/4852b399-0518-488d-8186-587e52941170`
   - **Пример ответа**:
   ```json
    {
       "client_id": "4852b399-0518-488d-8186-587e52941170",
       "access_token": "some_access_token"
    }
   ```
   - **Куки**: Refresh токен устанавливается в куки браузера.
   - **Имя куки**: `refresh_token`
   - **Свойства куки**:
      - **Путь**: `/auth`
      - **HTTPOnly**: Да
      - **Secure**: Нет

2) Обновление токенов
   - **Эндпоинт**: `GET /auth/token/refresh`
   - **Описание**: обновляет пару токенов.
   - **Пример запроса**: `GET http://localhost:8080/auth/token/refresh` и Access токен в `Header Authorization`
   - **Пример ответа**:
   ```json
    {
       "client_id": "4852b399-0518-488d-8186-587e52941170",
       "access_token": "some_new_access_token"
    }
   ```

## Переменные окружения

Пример .env файла:

```
PORT=8080
DB_USER=postgres
DB_PASSWORD=postgres
DB_HOST=postgres
DB_PORT=5432
DB_NAME=clients
ACCESS_TTL=15m
ACCESS_SIGNING_KEY=9GQxrrHvROiN57pYYXKswtiX4mvux7uA
REFRESH_TTL=168h
```

## Требования для запуска

- Docker

## Начало работы

Склонируйте репозиторий, создайте .env файл и из папки auth-service-go запустите:

```docker network create auth_network && docker-compose up -d```