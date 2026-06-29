# IA para mitigacao

O recurso de IA local e opcional e vem desativado por padrao. Quando `AI_MITIGATION_ENABLED=false`, o GMJ-FLOW nao chama provider de IA e o servico Ollama nao sobe no compose normal.

## Configuracao

Variaveis principais no `.env`:

```env
AI_MITIGATION_ENABLED=false
AI_PROVIDER=ollama
AI_BASE_URL=http://gmj-flow-ollama:11434
AI_MODEL_PROFILE=recommended
AI_MODEL=qwen2.5:3b-instruct
AI_TIMEOUT_SECONDS=20
AI_MAX_TOP_FLOWS=30
AI_MAX_CONTEXT_CHARS=12000
AI_ALLOW_AUTO=false
AI_REQUIRE_POLICY_VALIDATION=true
```

Perfis:

- `economical`: menor consumo, modelo padrao `qwen2.5:1.5b-instruct`, recomenda pelo menos 4 GB livres.
- `recommended`: equilibrio, modelo padrao `qwen2.5:3b-instruct`, recomenda pelo menos 8 GB livres.
- `strong`: analise mais rica, modelo padrao `qwen2.5:7b-instruct`, recomenda pelo menos 16 GB livres.

## Subir Ollama

O servico de IA usa profile do Docker Compose e nao sobe com `docker compose up -d`.

```bash
docker compose --profile ai up -d gmj-flow-ollama
```

Baixe somente o modelo que pretende usar:

```bash
docker compose --profile ai exec gmj-flow-ollama ollama pull qwen2.5:1.5b-instruct
docker compose --profile ai exec gmj-flow-ollama ollama pull qwen2.5:3b-instruct
docker compose --profile ai exec gmj-flow-ollama ollama pull qwen2.5:7b-instruct
docker compose --profile ai exec gmj-flow-ollama ollama pull llama3.2:1b
docker compose --profile ai exec gmj-flow-ollama ollama pull llama3.2:3b
```

## Seguranca operacional

A IA e apenas copiloto: analisa a anomalia, os flows relacionados e candidates ja montados pelo backend. Ela nunca escreve no pipe ExaBGP, nunca altera policy e nunca renderiza o comando final. O backend continua responsavel por gerar candidates deterministicos, validar policy, renderizar FlowSpec e exigir aprovacao humana.
