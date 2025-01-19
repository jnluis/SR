## Consider an application/solution for electric vehicle charging systems (kiosk with touch monitor).
Before starting charging, the user must authenticate (at the point, via wifi or Bluetooth connection, through a specific app)
Access is permitted through prior registration and with a login and password.
In his account, the user can see and change: Name, Email, telephone number, address, vehicle details, CC details, taxpayer number, consumption history, invoice history (monthly), associated credit card for direct payment, and other account settings (payment type, Discount code, etc.)

## 1- Describe a generic project plan (secure development) covering at least the specification part of the system (not the app), development, testing and acceptance/installation.

R:
Para o desenvolvimento deste projeto, é importante que se aplique o princípio de segurança by design desde o dia 0.
Assim, para a especficação de requisitos daquilo que vai ser o nosso sistema, devemos começar por reunir com os stakeholders, para definirmos métricas e regras de compliance, assim como a definição e uso de cryptotraphic standards.
Depois vão ser especificados os requisitos tanto de design, funcionais e não funcionais como de segurança e aplicado algum modelo de threat modelling (STRIDE por exemplo). Desta fase saem as tecnologias que vão ser utilizadas na parte de desenvolvimento. 

Já na parte de desenvolvimento, deve ser usado algum tipo de version control como o git, e deve ser usado o DevSecOps para automação do projeto de CI/CD.
Além disso, devem ser usadas ferramentas de análise de código, tanto estático (SAST), como dinâmico (DAST), como é o caso do SonarQube.
Já na parte de testes, devem ser definidos quality gates que o código deve passar antes de alcançar a fase de produção, e para isso devem ser feitos tanto de carga, como unitários, performance, User Acceptance Testing (UAT) e ainda penetration testing.

Por último, na fase de aceitação e instalação, deve ser entregue toda a documentação desenvolvida, como por exemplo o relatório de ameaças, relatório dos testes efetuados, etc.
É também ainda necessário desenvolver um processo de resposta a incidentes.

## 2- In light of a security threat analysis applicable to this system:
### Identify the main security attributes that must be taken into account, and briefly explain each of them with some examples (minimum 3 attributes, maximum 6).

R: Lista completa das propriedades: Ver slide 8 dos security requirements
Confidencialidade: Assegura que a informação sensível é apenas acessível a indivíduos ou sistemas autorizados;
Exemplo: Guarde as palavras-passe utilizando algoritmos de hashing fortes, como o bcrypt.

Integridade: Assegura que os dados são exatos, consistentes e protegidos contra modificações não autorizadas; 
Exemplo: Implementar verificações de integridade da base de dados com registos de transacções.

Disponibilidade: Assegura que o sistema e os seus serviços estão acessíveis quando necessário.
Exemplo: Utilize load balancers e infraestrutra na cloud escaláveis para lidar com tráfego elevado.

Authentication: Garante que apenas os utilizadores ou dispositivos legítimos podem aceder ao sistema.
Exemplo: Utilizar a autenticação multifactor (por exemplo, palavra-passe + OTP baseada em aplicações).

## 3- Write between 5 and 10 requirements related to the functional safety of the system, covering topics related to the attributes presented in question 2. 
### Carry out this mapping, even if some requirements map with more than one attribute.

R: 
Confidencialidade:
a) O modelo de controlo de acesso baseado em funções deve ser aplicado como principal mecanismo de controlo de acesso. 
b) Os sais das passphrases de autenticação do utilizador devem ser obtidos utilizando um gerador de números pseudo-aleatórios criptograficamente seguro criptograficamente seguro que se baseie na funcionalidade do sistema operativo.

Integridade:
a) Sistema de monitorização de logs deve encontrar-se à parte do resto do sistema;

Disponibilidade:
a) A conexão do quiosque ao Wifi tem de ser constante e o seu downtime não deve ser superior a 15 minutos por dia.

Authentication:
a) O sistema deve impor a utilização de um mecanismo OTP (one-time password ) para além do mecanismo existente baseado na palavra-passe para todos os utilizadores, a fim de realizar a autenticação multifactor.
b) O sistema deve usar WPA3 nas comunicações Wifi.

## 4- Define a set of tests to confirm the correct implementation of the requirements written in question 3. 
### Map each test case to the respective requirement(s).

R:
1 - Criar vários utilizadores com funções diferentes. Tentar ações restritas a funções específicas, tais como como aceder a definições administrativas com uma conta não-administrador. Verificar se os utilizadores só podem executar ações permitidas por funções que lhe foram atribuídas e que as tentativas não autorizadas são bloqueadas e registadas.
2 - Registar vários novos utilizadores com a mesma palavra-passe através da interface de front-end da aplicação. Verifique na base de dados se cada palavra-passe é com um sal exclusivo e que os valores de sal estão a ser gerados utilizando o sistema operativo gerador de números pseudo-aleatórios do sistema operativo, monitorizando as chamadas da API do sistema para o seu CSPRNG.
3 - Verificar que os logs se encontram em servidor ou serviço diferentes, e ainda penetration testing para confirmar que não é possível fazer path transversal e entrar nesse mesmo serviço.
4 - Simular um volume alto de requests num determinado período de tempo, para verificar que a conexão se mantém constante. Além disso, monitorizar a rede wi-fi e verificar tempos de downtime.
5 - Tentar fazer login com as credenciais corretas, mas sem o OTP e confirmar que o login não é possível. Verificar que o OTP realmente é de uso único e que tem um TTL.
6 - Confirmar nas definições da rede que o WPA3 está ligado. Depois disso, usar o Wireshark para verificar que nenhuma informação está a ser passada em plaintext e ainda executar um MITM, para confirmar que as proteções do WPA3 (nomeadamente através do SAE handshake) preveninem de uma exploitation bem sucedida.

## 5- To test the robustness of the solution, provide the following data:
   ### 1. List of all internal and external interfaces of the solution.
   ### 2. Name and describe (up to 100 words each) two security attacks that could be discovered when applying a penetration testing methodology.
   ### 3. Present 3 solutions to prevent DOS attacks (Denial-of-Service).

R:
1. List of Internal and External Interfaces

Internal Interfaces-

   - Authentication Module: Validates user credentials against the database.

   - Database Management System: Stores user data, vehicle details, payment information, and logs.

   - Session Management System: Handles active user sessions for charging and account activities.

External Interfaces-

- Mobile Application: Connects via Wi-Fi/Bluetooth to authenticate users and manage charging sessions.

- Payment Gateway: Processes credit card payments securely through third-party providers.

- Vehicle Communication Module: Interfaces with the vehicle's software to monitor and optimize charging.

- Wi-Fi/Bluetooth Network: Facilitates communication between the kiosk and the user devices.

- Cloud-Based Backend Services: Supports remote data storage, updates, and analytics.
Administrative Portal: Provides system administrators with tools for monitoring and management.

2. Two Security Attacks Discovered During Penetration Testing

1. SQL Injection Attack

An attacker attempts to inject malicious SQL statements into input fields to manipulate the database. For example, injecting a query to gain unauthorized access to user data or payment details. This vulnerability could expose sensitive information, compromise data integrity, and even lead to a full database breach.

2. Man-in-the-Middle (MITM) Attack

An attacker intercepts the communication between the user's mobile app and the kiosk or backend server via an unsecured Wi-Fi connection. This allows the attacker to eavesdrop on sensitive data, modify transaction details, or steal login credentials, posing a significant risk to confidentiality and authenticity.

3. Solutions to Prevent Denial-of-Service (DoS) Attacks

Rate Limiting

Implement rate limiting to restrict the number of requests a single IP address can send within a given timeframe. This helps prevent overwhelming the system with excessive traffic.
Web Application Firewall (WAF)

Deploy a WAF to detect and block malicious traffic patterns commonly associated with DoS attacks. It filters incoming traffic and prevents potential overloads.
Redundancy and Load Balancing

Use redundant systems and load balancers to distribute traffic across multiple servers. This prevents a single server from becoming a bottleneck and mitigates the impact of large-scale DoS attacks.

## 6- The customer identified 4 threats that they want to see resolved with the solution itself (without external interventions or service interruptions), and these are:
   ### • A) Installation of viruses or malware through the terminal
   ### • B) Improper access to terminal configuration functions (must only be allowed with the “maintenance” user)
   ### • C) Obtaining confidential data from another user
   ### • D) Using someone else’s account to top up

### As part of a threat analysis (hazard analysis), provide, for each threat listed by the customer, the following information:
   #### 1- Possible consequences;
   #### 2- Possible causes;
   #### 3- Some measures to implement/adopt to eliminate the threat.

R: 
Threat A: Installation of Viruses or Malware Through the Terminal

Possible Consequences:

- Unauthorized access to the system and data.
- Corruption or deletion of user and system data.
- Disruption of terminal functionality and user services.

Possible Causes:

- Use of unauthorized USB devices or external media.
- Downloading malicious files through insecure connections.
- Lack of security in software updates or third-party applications.

Measures to Eliminate the Threat:

- Disable all USB ports and external media access except for maintenance purposes.
- Implement a secure software update mechanism with digital signatures.
- Use anti-malware software to detect and prevent installation of malicious programs.
- Enforce network security policies to block access to unauthorized or untrusted websites.

Threat B: Improper Access to Terminal Configuration Functions

Possible Consequences:
- Unauthorized changes to terminal settings.
- System malfunction or reduced availability.
- Exposure of sensitive configurations that could lead to further exploitation.

Possible Causes:
- Lack of role-based access control for configuration functions.
- Weak or shared passwords for administrative accounts.
- Physical access to the terminal by unauthorized individuals.

Measures to Eliminate the Threat:
- Restrict configuration access to a specific "maintenance" user role with multi-factor authentication.
- Enforce strong password policies for maintenance accounts.
- Log all administrative actions for auditability.
- Physically secure the terminal to prevent unauthorized access.

Threat C: Obtaining Confidential Data from Another User
- Possible Consequences:
   - Compromise of user privacy and sensitive information (e.g., payment details).
   - Potential financial losses for users.
   - Loss of trust in the system by users.

- Possible Causes:
   - Insufficient encryption for data in transit or at rest.
   - Vulnerabilities in the system that allow unauthorized access to user data.
   - Poor session management leading to session hijacking.

Measures to Eliminate the Threat:

- Use strong encryption (e.g., AES for data at rest and TLS for data in transit).
- Implement strict access controls to prevent unauthorized data access.
- Regularly test the system for vulnerabilities and patch them promptly.
- Employ secure session management practices, such as session timeouts and unique session tokens.

Threat D: Using Someone Else’s Account to Top Up

Possible Consequences:

- Financial losses for the legitimate account owner.
- Abuse of the system for fraudulent activities.
- Reduced trust in the system’s security.

Possible Causes:

- Weak authentication methods, such as password-only access.
- Lack of mechanisms to detect unusual or fraudulent behavior.
- Sharing of login credentials by users.

Measures to Eliminate the Threat:

- Implement multi-factor authentication for user accounts.
- Use anomaly detection systems to identify and block suspicious account activity.
- Encourage users to set strong, unique passwords and educate them on not sharing credentials.
- Provide a mechanism for users to report and recover from unauthorized account access.

## 7- Which of the following components (select only one) is not related to the CIA triad?

#### A. Integrity

#### B. Availability

#### C. Reliability

#### D. Confidentiality

#### E. Non-Repudiation

R: Reliability
































