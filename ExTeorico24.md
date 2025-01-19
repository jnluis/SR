# Introdução:
O sistema de controlo das perfuradoras de poços de petróleo (PetroDrill) é um sistema integrado em todas as plataformas de exploração petrolífera de Portugal (Faro, Sines, Ilha do Pessegueiro, Setúbal, Nazaré Sul e Nazaré Norte, Figueira da Foz, Aveiro Sul e Aveiro Norte, Foz do Arelho, Madeira Norte (MAN) e Plataforma Integrada dos Açores (PIA)).

Este sistema deve ser desenvolvido, testado, certificado e integrado pela tua empresa.

Por um lado, o sistema está ligado a vários sensores dos equipamentos de perfuração e da plataforma petrolífera, por fibra óptica em duplicado (cabos separados e que passam por lados opostos da plataforma). Por outro lado, o sistema está ligado a uma central de comando e controlo, em Lisboa e com backup no Funchal, através de comunicação 5G e redundância por fibra óptica submarina.

Este sistema visa a monitorizar localmente o estado de “saúde” de todos os equipamentos de perforação e de suporte à mesma. Visando identificar tendências, falhas, alarmes e acidentes o mais cedo possível para garantir a segurança dos trabalhadores da PT Pretroleums, executar operações de intervenção rápida de manutenção e planear manutenções futuras, alterar parâmetros de perfuração e notificar as entidades de emergência para acções de salvamento. Para além de enviar toda a informação recolhida para as centrais de Lisboa e do Funchal, acções locais e imediatas podem ser despoletadas pelas equipas de intervenção rápida da plataforma. Portanto, a mesma terá uma ligação de emergência a equipamentos sonoros, de protecção contra sobreaquecimentos, fogos e explosões, e iluminação especial.
Estas plataformas são muitas vezes abordadas e invadidas por elemementos da GreenPeace, que são cada vez mais violentos e estas ocorrências devem também ser identificados e notificadas para as centrais nacionais. Muitos destes elementos chegam a usar meios pouco ortodoxos para destruir as plataformas ou parte das mesmas, chegando a causar feridos e derrames de petróleo.

Com vista a garantir a segurança de todos, do ambiente, e de assets da PT Petroleum, a tua empresa ficou encarregue de toda a componente segurança (security) e safety.

## 1: Explica, em dois parágrafos, quais as duas fases que consideras mais importantes, para o desenvolvimento da solução, e porque essas duas fases são importantes do ponto de vista de security e robustez da solução.

R: As 2 fases mais importantes do SDLC (Software Development Life Cycle) no desenvolvimento desta solução são a análise e planeamento de requisitos e implementação e testes.

Na primeira, as necessidades de segurança (security) e segurança funcional (safety) que o sistema deve ter vão ser definidas.
Além disso, nesta etapa vão ser identificados cenários de risco, como falhas nos próprios equipamentos, ataques externos e até ataques físicos (como é o caso dos ataques dos membros da GreenPeace).
Esta análise cuidadosa vai então permitir implementar controlos de segurança seguros, como uma bom processo de autenticação, cifra de dados sensíveis, e também sistemas de monitorização que permitem identificar qualquer anomalia em tempo útil.

Já a fase de implementação e testes é igualmente importante do ponto de vista de security e robustez já que é nesta que se vai verificar se o sistema cumpre com os requisitos definidos, através da simulação de cenários com condições reais, mas também adversas.
Assim, deve haver algum tipo de penetration testing, de forma a validar a proteção do sistema contra ataques externos, testes de desempenho e performance. É ainda importante fazer testes de integração, para verificar se os sistemas locais (de alarme, extenção de incêndios, etc) comunicam corretamente com as centrais nacionais.
Por último, tendo em conta que este sistema pode utilizar componentes tanto de hardware como software de entidades externas/parceiras, é também importante gerir o risco a elas associado.

## 2: À luz de uma análise de ameaças de segurança (threats analysis) aplicável a este sistema:

### a) Identifica os principais atributos de segurança que se devem ter em conta, e explicar brevemente cada um deles com alguns exemplos (3 atributos no mínimo, 6, no máximo).
### b) Lista 3 tipos de atacantes potenciais e quais seriam as suas motivações.
### c) Identifica uma vulnerabilidade (genérica) que deveria ser analizada para as possíveis tecnologias envolvidas.

R: 
a) Principais atributos de segurança a ter em conta:
Confidencialidade
Garante que informações sensíveis, como dados de operação ou alertas de segurança, sejam acessíveis apenas às pessoas e sistemas que tenham autorização para tal.
Exemplo: Proteger a comunicação entre sensores e a central de controlo em Lisboa contra interceções por grupos adversários.

Integridade
Assegura que os dados transmitidos e armazenados não sejam alterados ou corrompidos, intencionalmente ou acidentalmente. 
Exemplo: Garantir que os parâmetros de perfuração enviados da central de comando cheguem sem modificações que possam comprometer a segurança tanto dos trabalhadores como ser a causa de danos ambientais.

Disponibilidade
Certifica que o sistema e os serviços associados estão sempre acessíveis e operacionais.
Exemplo: A redundância de comunicação, como é o exemplo da fibra óptica em duplicado e o uso do 5G;

Não-repúdio
Assegura que as ações realizadas no sistema possam ser localizadas e atribuídas aos responsáveis, impedindo que indivíduos que tomaram determinadas ações as possam negar.
Exemplo: Em caso de de uma sabotagem identificada nos logs, ser possível identificar de onde surgiu o acesso indevido.

b) Ataques físicos: Por motivos ideológicos, como é o caso da GreenPeace, o sistema pode ser atacado por Hacktivistas que tentam sabotar as operações e gerar engagement na sociedade, para que se crie algum tipo de pressão social e que assim se denigra a imagem e reputação da PT Petroleum;
Ataque de negação de serviço: O setor petrolífero é um setor em que estão envolvidas várias nações, de vários espetros políticos, pelo que crackers governamentais podem tentar atacar o serviço, o que poderia levar a que a PT Petroleum tivesse de suspender as suas operações, tanto de exploração como venda, resultando numa diminuição da oferta e busca de novos fornecedores por parte dos seus clientes, se este ataque persistisse;
Ataques de ex-trabalhadores ou insiders com más intenções: Funcionários ou ex-trabalhadores, descontentes com a PT Petroleum, podem explorar as suas permissões internas ou conhecimento do sistema para o tentar sabotar, expondo dados confidenciais ou causando outro tipo de acidentes.

c) Vulnerabilidade genérica a ser analisada:
Gestão inadequada dos processos de autenticação e autorização
Se o sistema não implementar processos de autenticação e autorização robustos, pode existir acesso indevido aos equipamentos ou à rede. 
Por exemplo, credenciais hardcoded em sensores ou interfaces expostas na rede poderiam ser exploradas para alterar dados críticos ou interromper operações. 

## 3: Descrever 6 requisitos relacionados com a segurança funcional do sistema. Caso a descrição do sistema a desenvolver não permita identificar claramente requisitos fazer pressupostos (o cliente na maioria das vezes não faz bem ideia do que precisa, é perfeitamente normal fazer propostas lógicas e com sentido).
### Para cada requisito identificar quais os atributos de segurança, garantido que existe pelo menos um requisito relacionado com "Auditability".

R:

1- Deteção automática de falhas em sensores críticos:
O sistema deve monitorizar continuamente o funcionamento dos sensores de perfuração e suporte, identificando e notificando automaticamente falhas ou leituras inconsistentes em tempo real.

2- Resiliência a interrupções de comunicação:
O sistema deve assegurar redundância nas comunicações entre sensores e a central de comando, alternando automaticamente entre fibra óptica e 5G em caso de falha de uma das vias.

3- Processo de autentiçação adequados:
Qualquer comando enviado ao sistema, seja local ou remoto, deve passar por um mecanismo de autenticação forte (ex: uso de MFA) para prevenir alterações não autorizadas nos parâmetros de operação.

4- Resposta automática a emergências locais:
O sistema deve ser capaz de acionar alarmes de forma autónoma, sistemas anti-incêndio e dispositivos de iluminação de emergência quando identificar condições críticas, como sobreaquecimentos ou derrames.

5- Proteção contra acessos físicos não autorizados:
O sistema deve incluir um módulo para monitorizar e alertar sobre invasões físicas às plataformas, através do uso câmaras, sensores de movimento e controlo de acessos. Qualquer tentativa de acesso físico não autorizado deve ser comunicada imediatamente à central nacional.

6- Registo e auditoria de eventos do sistema
Todas as ações críticas, como alterações de parâmetros, alarmes, acessos ao sistema, e intervenções locais, devem ser registadas em logs protegidos contra alterações e com carimbo temporal (timestamp). Estes registos devem ser armazenados localmente e enviados para a central.

## 4: Definir um conjunto de testes (sob a forma de uma especificação simples) para confirmar a correcta implementação dos requisitos escritos na questão anterior (4). Mapear cada caso de teste ao(s) respectivo(s) requisito(s).
### Nota: Exemplo de especificação simples:
### Testar que no momento de registo de um novo utilizador, o mesmo recebe um email para confirmar o seu registo em menos de 5 minutos. Caso o mesmo nunca receber o email o registo fica pendente. Caso o email chegue depois de 5 minutos, o registo não deve ser confirmado e um novo email deve ser gerado.
### Nota: Um requisito pode perfeitamente ser não testável de forma dinâmica, nesse caso apresenta como o mesmo poderá ser verificado.

R: Os testes têm a numeração do seu respetivo requisito

1. Simular uma falha num sensor crítico (desconexão, envio de dados corrompidos ou inconsistentes) e verificar se:

Um alerta é gerado e enviado à interface local e à central de comando.
Verificação:
Observar logs do sistema para confirmar a deteção e envio do alerta.
Confirmar que o alerta aparece tanto na interface local como na central.

2. Desligar manualmente a comunicação por fibra óptica e verificar se:

O sistema alterna para comunicação 5G automaticamente.
Não ocorre perda de dados durante a mudança de canal de comunicação.
Verificação:
Comparar os dados recebidos pela central antes e depois da interrupção.
Confirmar logs que registem a transição do canal de comunicação.

3. Simular o envio de um comando não autenticado ao sistema e verificar se:

O sistema rejeita o comando com uma mensagem de erro e escreve um log com a operação mal sucedida.
O comando não afeta os parâmetros de operação.
Verificação:
Confirmar logs de rejeição de comando.
Verificar que os parâmetros de operação permanecem inalterados.

4. Executar ações críticas no sistema, como alteração de parâmetros e disparo de alarmes, e verificar se:

Cada ação é registada com um TimeStamp correto.
Os registos são armazenados localmente e enviados à central.
Os registos não podem ser alterados manualmente.
Verificação:
Comparar os registos locais e os recebidos pela central para confirmar integridade.

5. Simular um sobreaquecimento de um equipamento e verificar se:

Alarmes sonoros e visuais são ativados de forma automática.
O sistema anti-incêndio é ativado, caso necessário.
O alerta é enviado à central de comando.
Verificação:
Observar logs do sistema e confirmar ações desencadeadas.

6. Simular uma tentativa de acesso não autorizado (ex.: sem cartão de acesso ou utilizando credenciais inválidas) e verificar se:

O acesso é negado.
Um alerta é gerado e enviado à central.
A tentativa é registada no log com informações detalhadas (local, hora, tentativa).
Verificação:
Verificar o sistema de registo de acessos para confirmar o log da tentativa.
Confirmar o envio de alerta à central.

## 5: Com vista a testar a robustez da solução, fornecer os seguintes dados:
   ### • Lista de todas as interfaces internas e externas da solução.
   ### • Nomear e descrever (até 100 palavras cada) dois ataques de segurança que poderiam ser descobertos ao aplicar uma metodologia de penetration testing.
   ### • Apresentar 2 soluções ou boas práticas para evitar ataques de XSS (Cross site scripting).

R:
a) 
Interfaces internas:
Conexões entre os sensores e sistema central da plataforma, ou seja, comunicação por fibra ótica interna para monitorização dos equipamentos.

Sistema de controlo local, isto é, a interface para as equipas de manutenção e intervenção rápida ajustarem parâmetros ou monitorizarem a plataforma.

Interfaces externas:
Rede 5G, que é usada para comunicação entre a plataforma petrolífera e a central de comando (Lisboa/Funchal), usada para enviar dados e receber comandos.

Fibra ótica submarina, que é usada para comunicação redundante entre a plataforma e a central, garantindo maior robustez em caso de falhas.

Acesso físico às plataformas, em que exite uma interface/barreira de segurança física para entrada nas instalações.

Dispositivos de emergência locais, ou seja, os alarmes, sistemas anti-incêndio e iluminação especial que são acionados de forma automática.

b) Ataque detetáveis através de penetration testing:
1- Ataque de Man-in-the-Middle (MitM)
O atacante interceta a comunicação entre sensores e o sistema central ou entre a plataforma e a central de comando via 5G ou fibra ótica. Durante o ataque, o cracker pode alterar ou corromper dados, compromentendo a integridade dos mesmos;

2- Ataque de Escalada de Privilégios
O atacante, explorando falhas em autenticação ou permissões mal configuradas, obtém acesso administrativo (rrot) ao sistema local ou remoto. Isso pode permitir alterações não autorizadas, desativação de alarmes ou manipulação de dispositivos de emergência.


c) Soluções para evitar XSS:
1-  Filtrar os inputs da maneira mais estrita possível
2- Usar response headers como Content-Type e X-Content-Type-Options

## 6: Pensando agora no sistema que deve ser implementado, no ambiente onde ele vai operar, nas possíveis tecnologias envolvidas e numa potential arquitectura, quais seriam,  em conclusão, os 5 (cinco) principais princípios de design de segurança que não poderiam ser ignorados para este projeto?

R:

1. Apply Defense in Depth
Implementar múltiplas camadas de segurança em todos os níveis do sistema, assegurando que um falha numa camada não compromete a integridade de todo o sistema.

2. Run with Least Privilege
Cada utilizador, sistema e processo deve operar com os menores privilégios possíveis para executar suas funções, limitando o impacto de falhas.

3. Detect Intrusions
Monitorizar atividades no sistema para identificar intrusões ou comportamentos anómalos. Isso inclui o uso de IDS (Intrusion Detection Systems), IPS (Instrusion Prevention Systems) e SIEM, com alertas em tempo real.

4. Fail Securely
Garantir que o sistema permaneça num estado seguro em caso de falha.

5. Log All Security Relevant Information
Registar todas as ações críticas e eventos de segurança, com proteção contra alterações e monitorização regular dos logs para deteção de anomalias.

## 7: Foram-lhe fornecidos um conjunto de requisitos de software relacionados com cibersegurança. Alguns destes requisitos estão bem escritos e seguem os critérios SMART, enquanto outros têm problemas que os tornam menos eficazes. A sua tarefa é analisar estes requisitos e responder às seguintes questões:

### Parte A: Identificação e Análise (0,5 pontos)

Identificar Problemas: Reveja os cinco requisitos seguintes e identifique pelo menos um problema com cada requisito. Explique porque o requisito não é específico, mensurável, atingível, relevante ou temporal (SMART).

Requisito 1: O sistema deve garantir alta disponibilidade em todos os momentos.

Requisito 2: O sistema deve proteger os dados do utilizador contra acesso não autorizado.

Requisito 3: O sistema deve garantir a integridade dos dados.

Requisito 4: O sistema deve usar métodos de autenticação fortes.

Requisito 5: O sistema deve registar todas as atividades do utilizador.

### Parte B: Melhoria (0,5 pontos)

Reescrever Requisitos: Reescreva os cinco requisitos da Parte A para torná-los SMART. Certifique-se de que cada requisito seja específico, mensurável, atingível, relevante e temporal.

### Parte C: Avaliação (0,5 pontos)

Avaliar Requisitos SMART: Reveja os cinco requisitos SMART seguintes e explique porque cada um cumpre os critérios SMART. Destaque os aspetos específicos, mensuráveis, atingíveis, relevantes e temporais de cada requisito.

Requisito 1: O sistema deve atingir uma disponibilidade de 99,9% durante o primeiro ano de operação, excluindo períodos de manutenção agendados.

Requisito 2: O sistema deve encriptar todos os dados do utilizador em repouso e em trânsito usando encriptação AES-256 até ao final do 2º trimestre de 2025 para proteger contra acesso não autorizado.

Requisito 3: O sistema deve implementar checksums para todas as transferências de dados para garantir a integridade dos dados, com uma taxa de sucesso de verificação de 99,5% ou superior até ao final do 3º trimestre de 2025.

Requisito 4: O sistema deve implementar autenticação multi-fator (MFA) para todos os logins de utilizadores até ao final do 1º trimestre de 2025, exigindo pelo menos duas formas de verificação (ex: palavra-passe e OTP).

Requisito 5: O sistema deve registar todas as ações administrativas e reter esses registos por um mínimo de um ano, com os registos a serem revistos mensalmente para quaisquer atividades suspeitas a partir do 2º trimestre de 2025.

R: 

Parte A:

Requisito 1- Não é mensurável, pois deve ser definido o que são todos os momentos;

2- Não especifica o que é acesso não autorizado

3- Não especifica como é que se pode garantir a integridade desses dados

4- Não define métodos de autenticação fortes

5- Não define como é que se podem registar as atividades do utilizador

Parte B:

Requisito 1: O sistema deve garantir disponibilidade de 0.999 (8.76 horas de down-time por ano)

Requisito 2: O sistema deve proteger os dados do utilizador contra acesso não autorizado, usando um modelo RBAC. garantindo que tentativas de acesso não autorizado são detetadas e registadas

Requisito 3: O sistema deve garantir a integridade dos dados, usando funções de hash como o SHA-256 

Requisito 4: O sistema deve usar métodos de autenticação fortes, como o uso de MFA (Multi Factor Authentication) e possiblidade de uso de OTP's (One Time Passwords)

Requisito 5: O sistema deve registar todas as atividades do utilizador. Para isso, podem ser logs, que se encontram cifrados, com acesso apenas a administradores, e que ficam na base de dados por um período mínimo de 2 anos

Parte C:

Requisito 1: Define um intervalo temporal que o sistema deve alcançar de disponibilidade, especificando qual é esta percentagem de tempo.

Requisito 2: Define um deadline temporal até quando é que o requisito deve ser implementado, especificando qual a cifra a usar e quando deve ser usada.

Requisito 3: Define um deadline temporal e define uma taxa de sucesso especifica

Requisito 4: Define um deadline temporal e especifica quais os métodos de autenticação que suportam o requisito de MFA

Requisito 5: Define o tempo que os registos devem ser guardados, e uma data a partir dos quais devem ser revistos de forma regular.

## 8: Considerando apenas um dos 3 ciberataques que ocorreram em 2024 (ver abaixo), pesquisa informações sobre o mesmo e reporta o seguinte:

### Qual ou quais dos princípios da tríade CIA foi ou foram explorados no ciberataque, e explica.
### Que interface ou interfaces foram utilizados para efetuar o ciberataque?
### Que medidas (software ou outras) foram aplicadas para (já aplicadas ou que aplicarias):
- detetar o ciberataque; 
- limitar ou impedir a continuação do mesmo;
- corrigir o problema;

Escolhe um destes 3 ciberataques que ocorreram em 2024 para responder a esta pergunta:

1. Violação de Dados da Ticketmaster: Em maio de 2024, a Ticketmaster sofreu uma grande violação que comprometeu os dados de 560 milhões de clientes.

2. Ciberataque a um Satélite Copernicus: Em julho de 2024 hackers russos atacaram o programa de satélites Copernicus, expondo vulnerabilidades no software usado para as operações dos satélites.

3. Violação de Dados da AT&T: Em março de 2024, a AT&T sofreu uma violação de dados que afetou mais de 73 milhões de clientes atuais e antigos. Informações pessoais, incluindo números de Segurança Social e detalhes de contas, foram expostas. Dados pessoais expostos de mais de 73 milhões de indivíduos, incluindo 7,6 milhões de clientes atuais e 65,4 milhões de antigos clientes.

R: Escolhi a notícia 1. Violação de Dados da Ticketmaster

1- Foi violado o princípio da Confidencialidade, já que depois da exploração da vulnerabilidade, os dados pessoais de milhões de clientes foram exfiltrados e foram encontrados à venda em fóruns da dark web;
2- Foi explorada uma vulnerabilidade no portal de atendimento ao cliente da TicketMaster;
3- 
Para detetar o ciberataque, faria uso de um SIEM, que daria alerta de tráfego estranho ou comportamentos incomuns no sistema.
A ticketmaster desligou os sistemas que foram afetados e notificou os seus clientes;
Eu daria fix à vulnerabilidade, verificando ainda se a mesma não se encontra noutro ponto do sistema.