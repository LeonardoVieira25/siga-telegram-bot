# Projeto Bot do Telegram para Notificações

Este projeto é um bot do Telegram projetado para enviar notificações sobre novas notas publicadas.

O projeto consiste em dois programas Python:

1. Um programa responsável por registrar novos usuários.
2. Outro programa responsável pelo web scraping e envio de notificações.

O web scraping é realizado com curl, sem a necessidade de simular um navegador.

Este sistema armazena o hash da senha dos usuários cadastrados, além do login dos mesmos.

## Configuração

Para utilizar o sistema, é necessário configurar a variável de ambiente `TELEBOT_TOKEN` com a API key do seu bot no Telegram.