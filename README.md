# kubsei-users-java

Authentication and user accounts (REST). Issues the JWTs that kubsei-gateway and kubsei-editor verify.
Contract: [kubsei-users-lib-java](https://github.com/kubsei/kubsei-users-lib-java) (`openapi.yaml`); controllers implement the generated `AuthApi` / `UsersApi`.

## Run

```bash
export JWT_SECRET=...            # same in users, editor and gateway, >= 32 bytes
export GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=...
mvn spring-boot:run              # http://localhost:8081
```

| Variable | Default |
|---|---|
| `MONGODB_URI` | `mongodb://localhost:27017/kubsei_users` |
| `JWT_SECRET` | required |
| `JWT_ISSUER` | `kubsei` |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | required |
| `OAUTH2_SUCCESS_URL` | `http://localhost:3000/workspace` |
| `OAUTH2_FAILURE_URL` | `http://localhost:3000/login?error=true` |
| `SERVER_PORT` | `8081` |

Reach it through the gateway: Google login redirects are built from the gateway's `X-Forwarded-*` headers.
