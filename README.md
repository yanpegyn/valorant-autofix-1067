# Auto Fix 1067

## Correções Disponíveis

- Checagem de TPM 2.0.
- Checagem de Secure Boot.
- (Precisa de correções) Ativação do "Usar Unicode UTF-8 para suporte de linguagem mundial".
- Limpeza do Package Cache.
- Alteração de DNS para o Cloudflare, tanto em IPV4 quanto IPV6, ambos usando DNS sobre HTTPS para maior privacidade e segurança.
- Limpeza do DNS Cache.
- Definição de regra de inicio do Riot Vanguard como automático.
- (Precisa de validar) Reinstalação do Vanguard.
- (Precisa de validar) Limpeza de Logs do Vanguard.
- Adição do Vanguard e do Valorant nas exceções de Firewall, tanto para Inbound, quanto Outbound.
- (Experimental) Busca por dispositivos suspeitos, como KVMs, que podem ser mal interpretados pelo Vanguard.

## Possivel de reverter

- Desfazer alteração do DNS.
- Remoção das exceções de Firewall.
- (TODO) Desabilitar "Usar Unicode UTF-8 para suporte de linguagem mundial".

## Possíveis Melhorias

- Incluir uma forma de instalar / reparar os "Visual C++ Redistributable Runtimes".
  - Por enquanto instalar de forma manual, sugestão: https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/.
- Checagem de Drivers de GPU.
  - Verificar Drivers AMD.
  - Verificar Drivers NVIDIA.
  - Verificar Drivers Intel.
