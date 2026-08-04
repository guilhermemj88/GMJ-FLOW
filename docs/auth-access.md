# Usuários, autenticação e RBAC

O GMJ-FLOW usa um único sistema de autenticação: a tabela SQLite `users`, hashes bcrypt, JWT HS256 e o middleware HTTP existentes. A evolução adiciona sessões persistentes revogáveis e permissões efetivas, sem guardar JWTs ou senhas em texto puro.

## Primeiro administrador

Uma base nova não recebe uma senha conhecida. Para inicializar a primeira conta, defina temporariamente `GMJFLOW_INITIAL_ADMIN_PASSWORD` com ao menos `GMJFLOW_AUTH_PASSWORD_MIN_LENGTH` caracteres. A conta `admin` é criada uma única vez, com `must_change_password=true`. Remova a variável depois do bootstrap.

Como o `docker-compose.yml` existente não foi alterado, injete a variável somente no processo de bootstrap por um mecanismo de segredo autorizado para o ambiente. Não coloque a frase-senha em arquivo versionado, argumento de linha de comando ou histórico do shell.

Bases existentes não têm seus hashes alterados. As migrações são idempotentes e não sobrescrevem permissões de perfis já customizadas.

## Decisão de acesso

As permissões efetivas são calculadas em cada requisição:

```text
permissões permitidas pelo perfil
+ overrides allow do usuário
- overrides deny do usuário
```

`deny` prevalece sobre herança. O JWT não é usado como fonte permanente de permissões: o middleware recarrega o usuário, sua versão e suas permissões do SQLite. Desativação e troca/redefinição de senha revogam acessos existentes.

## Endpoints administrativos

- Autenticação: `/api/v1/auth/login`, `/me`, `/logout`, `/change-password`, `/sessions` e `/revoke-sessions`.
- Usuários: `/api/v1/users` e ações `reset-password`, `revoke-sessions`, `enable` e `disable`.
- Perfis e catálogo: `/api/v1/roles` e `/api/v1/permissions`.
- Auditoria: `/api/v1/audit` e `/api/v1/audit/users/{id}`.

Os endpoints antigos `/api/auth/*` continuam disponíveis para compatibilidade.

## Controles configuráveis

- `GMJFLOW_AUTH_PASSWORD_MIN_LENGTH` (mínimo imposto: 10)
- `GMJFLOW_AUTH_MAX_FAILED_ATTEMPTS`
- `GMJFLOW_AUTH_LOCK_MINUTES`
- `GMJFLOW_AUTH_RATE_LIMIT_ATTEMPTS`
- `GMJFLOW_AUTH_RATE_LIMIT_WINDOW_SECONDS`

O rate limit é local ao processo. Em uma implantação futura com múltiplas réplicas, ele deve ser movido para um armazenamento compartilhado.

## Verificação manual local

1. Use uma cópia descartável do banco e configure a senha inicial apenas se a cópia estiver vazia.
2. Entre como administrador e confirme a troca obrigatória de senha.
3. Crie um viewer e um operator; valide menus ocultos e respostas 403 ao chamar diretamente uma rota de mutação.
4. Aplique overrides `allow` e `deny`, atualize a sessão e confira a decisão imediata.
5. Redefina a senha e desative uma conta com sessão ativa; confirme que o token anterior recebe 401.
6. Tente desativar, excluir ou retirar `users.manage_permissions` do último administrador; espere 409.
7. Confira a auditoria sem senhas, hashes ou tokens e com o `X-Request-ID` usado no teste.
