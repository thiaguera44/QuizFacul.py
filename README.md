GRUPO - 05

Bruno Henrique - 322129027
Caio Vieira – 32222235	
Felipe Gabriel – 32227639
Sérgio de Souza – 32220410
Thais Cristina – 322210135
Thiago Rocha – 32222617




Projeto de Sistema de Quizzes
Este projeto é um sistema de quizzes desenvolvido com Flask e SQLite. Ele permite que os usuários se registrem, façam login, criem quizzes, respondam quizzes e vejam seus resultados.

Visão Geral
O sistema de quizzes possui as seguintes funcionalidades:

Registro e login de usuários.
Criação de quizzes com múltiplas perguntas e respostas.
Visualização de quizzes criados.
Realização de quizzes e visualização de resultados.
Configurações de perfil para atualização de email e senha.



Instalação
Clone o repositório:

sh
Copiar código
git clone https://github.com/seu-usuario/quiz_system.git
cd quiz_system
Crie e ative um ambiente virtual:

sh
Copiar código
python -m venv venv
source venv/bin/activate  # No Windows, use `venv\Scripts\activate`
Instale as dependências:

sh
Copiar código
pip install -r requirements.txt
Inicialize o banco de dados:

sh
Copiar código
python init_db.py
Como Rodar o Projeto
Certifique-se de que o ambiente virtual está ativado.
Rode o aplicativo Flask:
sh
Copiar código
python app.py
Acesse o aplicativo no navegador em http://127.0.0.1:5000.


Detalhes das Funcionalidades
Registro e Login de Usuários
Os usuários podem se registrar com um nome de usuário, email e senha.
O login é feito com nome de usuário e senha.
As senhas são armazenadas de forma segura usando hashing.
Criação de Quizzes
Usuários autenticados podem criar quizzes com um título, descrição e múltiplas perguntas.
Cada pergunta pode ter múltiplas respostas, e o usuário pode marcar quais são as corretas.
Visualização de Quizzes
Todos os quizzes criados são listados na página de quizzes.
Realização de Quizzes e Resultados
Os usuários podem realizar quizzes e ver seus resultados imediatamente.
Configurações de Perfil
Usuários autenticados podem atualizar seu email e senha na página de configurações do perfil.
Contribuição
Contribuições são bem-vindas! Siga os passos abaixo para contribuir:



Contato
Para dúvidas ou sugestões, entre em contato com thirochag@gmail.com.

