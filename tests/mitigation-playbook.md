# GMJ-FLOW Mitigation Playbook

Regras operacionais iniciais usadas pelo motor deterministico de mitigacao:

- Preferir o bloqueio mais especifico primeiro: source /32 + destination /32 + protocolo + porta.
- Nao bloquear origem interna inteira sem porta por padrao.
- DNS/53, NTP/123, SSDP/1900, CLDAP/389, CHARGEN/19 e servicos sensiveis exigem aprovacao manual.
- Prefixos protegidos ou whitelisted bloqueiam acao automatica e exigem aprovacao manual.
- Flows pequenos com 1 a 2 pacotes e poucos bytes sao ruido provavel; priorizar concentracao real.
- Priorizar flows com maior combinacao de packets e bytes.
- Se o mesmo destino externo aparece em muitos ataques na mesma porta, considerar destination /32 + porta.
- Se o mesmo destino externo aparece em muitas portas, considerar destination /32 apenas com aprovacao manual.
- Nunca anunciar automaticamente candidates `analysis_only`, `never_announce` ou `manual_only`.
