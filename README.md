## Firewall Simulator

Este projeto em JavaScript simula um firewall que analisa e filtra o tráfego de entrada com base em várias políticas de segurança. O firewall é composto por três componentes principais: um motor de políticas, um firewall e um logger.
## Getting Started

Siga as instruções abaixo para configurar o projeto localmente.

### Pré-requisitos

Certifique-se de ter o **Node.js** e o **npm** instalados no seu ambiente. Você pode baixá-los [aqui](https://nodejs.org/).

### Instalação

1. Clone o repositório para a sua máquina local:

   ```bash
   git clone https://github.com/ViniciusPng/Firewall_Simulation.git

## Componentes

### 1. Policy Engine

O motor de políticas é responsável por avaliar o tráfego de entrada contra um conjunto de regras de segurança predefinidas. As regras são implementadas como classes que estendem uma classe base chamada `Rule`. Cada regra avalia um aspecto específico do tráfego de entrada, como:

- **Regra de Sistemas Operacionais Obsoletos**: Verifica se o sistema operacional do agente do usuário está desatualizado e vulnerável a ataques.
- **Regra de Ausência de Informações do Dispositivo**: Verifica se as informações do dispositivo do agente do usuário estão incompletas ou são suspeitas.
- **Regra de Caminho de Requisição Maliciosa**: Verifica se o caminho da requisição contém padrões ou palavras-chave suspeitas que possam indicar uma ameaça potencial.

O motor de políticas aplica essas regras para determinar se o tráfego será permitido ou bloqueado.

### 2. Firewall

O firewall gerencia a **lista de permissões** (whitelist), **lista de bloqueios** (blacklist) e **bloqueios temporários** de endereços IP. Também mantém um histórico de todas as ações tomadas sobre o tráfego de entrada. O firewall usa o motor de políticas para avaliar o tráfego e tomar decisões com base nas regras de segurança.

### 3. Logger

O logger é responsável por registrar todas as ações tomadas pelo firewall, incluindo o tráfego permitido e bloqueado. Os logs são gravados em um arquivo chamado `firewall.log`.

## Análise de Tráfego

O projeto inclui um **analisador de tráfego** que lê dados de tráfego de entrada a partir de um arquivo JSON e analisa as informações do agente do usuário utilizando a biblioteca `ua-parser-js`.

## Arquitetura

O projeto consiste nos seguintes componentes:

- **index.js**: Ponto de entrada principal do projeto que carrega as listas de permissões, bloqueios e dados de tráfego, aplicando as políticas de segurança ao tráfego.
- **policy.js**: Define as regras de segurança e o motor de políticas que avalia o tráfego de entrada.
- **firewall.js**: Implementa o firewall que gerencia as listas de permissões, bloqueios e bloqueios temporários de IPs, mantendo um histórico das ações tomadas.
- **logger.js**: Implementa o logger que registra todas as ações realizadas pelo firewall.
- **traffic.js**: Analisa os dados de tráfego de entrada a partir de um arquivo JSON e usa a biblioteca `ua-parser-js` para obter informações do agente do usuário.

![img](./img/shapes%20at%2024-09-13%2017.30.09.png)

## Funcionalidades

O projeto oferece as seguintes funcionalidades:

- Carrega dados de listas de permissões e bloqueios a partir de arquivos JSON.
- Analisa dados de tráfego de entrada a partir de um arquivo JSON.
- Analisa as informações do agente do usuário utilizando a biblioteca `ua-parser-js`.
- Avalia o tráfego de entrada com base em regras de segurança predefinidas.
- Toma decisões de permitir ou bloquear tráfego com base nas regras de segurança.
- Registra todas as ações do firewall no arquivo `firewall.log`.
- Mantém um histórico das ações tomadas sobre o tráfego de entrada.

## Medidas de Segurança Implementadas

- **Lista de Permissões (Whitelisting)**: Endereços IP na lista de permissões são autorizados a passar pelo firewall sem serem avaliados pelo motor de políticas.
- **Lista de Bloqueios (Blacklisting)**: Endereços IP na lista de bloqueios são bloqueados pelo firewall, e seu tráfego não é avaliado pelo motor de políticas.
- **Bloqueio Temporário**: Endereços IP temporariamente bloqueados são adicionados a uma lista de bloqueio temporário, e seu tráfego é bloqueado por um período especificado (12 horas neste projeto).
- **Rate Limiting**: O firewall verifica a taxa de requisições de cada endereço IP e bloqueia temporariamente endereços que excedem um limite pré-definido.

## Rastreabilidade e Reversibilidade de Ações

Todas as ações tomadas pelo firewall são registradas no arquivo `firewall.log`, incluindo tráfego permitido e bloqueado, facilitando o rastreamento e análise das ações. O histórico do firewall é mantido em memória, permitindo a reversão fácil de ações, se necessário.

Este projeto é uma simulação básica de firewall com capacidades de análise de tráfego e regras de segurança personalizadas.
## Insights e Análise dos Dados

Para realizar a análise, comecei dividindo os dados em duas categorias principais: **Cliente** e **Servidor**. A partir dessa divisão, foi possível conduzir uma análise mais detalhada dos dados que precisavam ser tratados.

Utilizando a biblioteca **Pandas** em Python, consegui realizar uma análise mais robusta, separando e agrupando os dados de forma eficiente. Isso permitiu a identificação de padrões importantes e possíveis ataques de segurança.

- Ao segmentar a coluna `ClientRequestUserAgent`, foram detectados padrões de uso de **sistemas operacionais obsoletos** ou sem suporte, o que pode abrir portas para **ataques de dia zero** (zero-day attacks), onde os invasores exploram vulnerabilidades conhecidas que não têm mais correções disponíveis.

- A ausência de informações completas no `ClientRequestUserAgent`, como a falta de dados sobre o dispositivo, pode ser um indício de **spoofing**, onde o atacante forja dados para mascarar sua verdadeira identidade.

- Ao agrupar as datas com os endereços IP, o excesso de requisições de alguns IPs tornou-se evidente, caracterizando um padrão de **ataques de negação de serviço distribuído (DDoS)**, onde múltiplas requisições rápidas sobrecarregam o servidor, tornando-o inacessível.

- A análise da coluna `ClientRequestPath` revelou tentativas de acesso a locais sensíveis ou com potenciais riscos de segurança. Esses padrões indicam possíveis **ataques de injeção de comando** (command injection) ou **tentativas de traversal de diretórios** (directory traversal), onde o invasor tenta acessar áreas protegidas do sistema, além de **tentativas de exploração de vulnerabilidades em aplicações web**.

Com uma análise mais aprofundada, outras falhas de segurança, como **força bruta** e **ataques de enumeração de recursos**, podem ser observadas, revelando mais vulnerabilidades que podem ser exploradas por atacantes. Esses insights são cruciais para o aprimoramento das políticas de segurança e proteção contra ameaças emergentes.

## Autor

- [Vinicius Cezario Rodrigues](https://www.linkedin.com/in/vinicius-cezario-rodrigues-6704401ab/)

