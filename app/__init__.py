from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_login import LoginManager, login_required, UserMixin
from flask_wtf import CSRFProtect
import sqlite3
import bcrypt

app = Flask(__name__)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)
app.secret_key = 'your_secret_key'  # Chave secreta para sessões

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Funções para o banco de dados SQLite
def conectar_bd():
    conn = sqlite3.connect('caminho_para_seu_banco_de_dados.db')
    conn.row_factory = sqlite3.Row
    return conn

def criar_tabela_usuarios():
    conn = conectar_bd()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            senha TEXT
        )
    ''')
    conn.commit()
    conn.close()

def adicionar_usuario(username, email, senha):
    conn = conectar_bd()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO usuarios (username, email, senha) VALUES (?, ?, ?)', (username, email, senha))
    conn.commit()
    conn.close()

def buscar_usuario_por_username(username):
    conn = conectar_bd()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM usuarios WHERE username = ?', (username,))
    usuario = cursor.fetchone()
    conn.close()
    return usuario

def buscar_usuario_por_email(email):
    conn = conectar_bd()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM usuarios WHERE email = ?', (email,))
    usuario = cursor.fetchone()
    conn.close()
    return usuario

def criar_tabela_quizzes():
    conn = conectar_bd()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS quizzes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT,
            descricao TEXT,
            criador_id INTEGER,
            FOREIGN KEY (criador_id) REFERENCES usuarios (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS perguntas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quiz_id INTEGER,
            texto TEXT,
            FOREIGN KEY (quiz_id) REFERENCES quizzes (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS respostas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pergunta_id INTEGER,
            texto TEXT,
            correta BOOLEAN,
            FOREIGN KEY (pergunta_id) REFERENCES perguntas (id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS resultados_quizzes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quiz_id INTEGER,
            usuario_id INTEGER,
            pontuacao INTEGER,
            FOREIGN KEY (quiz_id) REFERENCES quizzes (id),
            FOREIGN KEY (usuario_id) REFERENCES usuarios (id)
        )
    ''')
    conn.commit()
    conn.close()

# Funções de autenticação
def validar_credenciais(username, password):
    usuario = buscar_usuario_por_username(username)
    if usuario:
        hash_senha = usuario[3]
        return verificar_senha(password, hash_senha)
    return False

def criar_hash_senha(senha):
    return bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())

def verificar_senha(senha_digitada, hash_senha):
    return bcrypt.checkpw(senha_digitada.encode('utf-8'), hash_senha)

# Rotas Flask
@app.route('/')
def index():
    return 'Hello, World!'

# ROTA PARA PÁGINA DE LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if validar_credenciais(username, password):
            # Autenticação bem-sucedida, armazenar o nome de usuário na sessão
            session['username'] = username
            # Redirecionar para a home
            return redirect(url_for('home'))
        else:
            error = 'Credenciais inválidas. Tente novamente.'
            return render_template('login.html', error=error)
    return render_template('login.html')

# ROTA PÁGINA DE REGISTRO
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Verificar se o usuário já existe
        if buscar_usuario_por_username(username):
            error = 'Nome de usuário já está em uso. Por favor, escolha outro.'
            return render_template('register.html', error=error)
        
        # Verificar se a senha e a confirmação de senha são iguais
        if password != confirm_password:
            error = 'As senhas não coincidem. Por favor, tente novamente.'
            return render_template('register.html', error=error)
        
        # Criar hash da senha
        hashed_password = criar_hash_senha(password)
        
        # Adicionar o novo usuário ao banco de dados
        adicionar_usuario(username, email, hashed_password)
        
        # Redirecionar para a página de login após o registro bem-sucedido
        return redirect(url_for('login'))
    
    return render_template('register.html')

# ROTA PÁGINA INICIAL
@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    conn = conectar_bd()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM quizzes')
    quizzes = cursor.fetchall()
    conn.close()
    
    return render_template('home.html', quizzes=quizzes)

@app.route('/select_theme')
def select_theme():
    return render_template('quiz_start_page.html')

@app.route('/start_quiz/<int:quiz_id>')
def start_quiz(quiz_id):
    conn = conectar_bd()
    cursor = conn.cursor()
    
    try:
        # Obter título do quiz
        cursor.execute('SELECT titulo FROM quizzes WHERE id = ?', (quiz_id,))
        quiz_titulo = cursor.fetchone()
        
        if not quiz_titulo:
            abort(404, description="Quiz não encontrado")  # Retorna erro 404 se o quiz não existir
        
        # Obter perguntas e respostas do quiz
        cursor.execute('''
            SELECT p.id AS pergunta_id, p.texto AS pergunta_texto, 
                   r.id AS resposta_id, r.texto AS resposta_texto, r.correta AS resposta_correta
            FROM perguntas p
            JOIN respostas r ON p.id = r.pergunta_id
            WHERE p.quiz_id = ?
        ''', (quiz_id,))
        
        perguntas_respostas = cursor.fetchall()
        
        # Organizar as perguntas e respostas em um formato adequado para o template
        quiz_perguntas = []
        pergunta_atual = None
        respostas_atual = []
        
        for pr in perguntas_respostas:
            if pergunta_atual is None or pergunta_atual['pergunta_id'] != pr['pergunta_id']:
                if pergunta_atual is not None:
                    quiz_perguntas.append((pergunta_atual, respostas_atual))
                pergunta_atual = {
                    'pergunta_id': pr['pergunta_id'],
                    'pergunta_texto': pr['pergunta_texto']
                }
                respostas_atual = []
            respostas_atual.append({
                'resposta_id': pr['resposta_id'],
                'resposta_texto': pr['resposta_texto'],
                'resposta_correta': pr['resposta_correta']
            })
        
        # Adicionar a última pergunta ao quiz_perguntas
        if pergunta_atual is not None:
            quiz_perguntas.append((pergunta_atual, respostas_atual))
        
        conn.close()
        
        return render_template('start_quiz.html', quiz_titulo=quiz_titulo['titulo'], quiz_perguntas=quiz_perguntas, quiz_id=quiz_id)
    
    except Exception as e:
        print(f"Erro ao carregar quiz: {e}")
        conn.close()
        abort(500, description="Erro ao carregar quiz")



# Definindo o endpoint para exibir os resultados do quiz
@app.route('/quiz_results/<int:quiz_id>', methods=['POST'])
def quiz_results(quiz_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    respostas_usuario = request.form
    pontuacao = 0
    total_perguntas = 0
    
    conn = conectar_bd()
    cursor = conn.cursor()
    
    for pergunta_id, resposta_id in respostas_usuario.items():
        cursor.execute('SELECT correta FROM respostas WHERE id = ?', (resposta_id,))
        correta = cursor.fetchone()[0]
        if correta:
            pontuacao += 1
        total_perguntas += 1
    
    usuario = buscar_usuario_por_username(session['username'])
    usuario_id = usuario[0]
    
    cursor.execute('INSERT INTO resultados_quizzes (quiz_id, usuario_id, pontuacao) VALUES (?, ?, ?)', (quiz_id, usuario_id, pontuacao))
    conn.commit()
    conn.close()
    
    return render_template('quiz_results.html', pontuacao=pontuacao, total_perguntas=total_perguntas)

@app.route('/last_results')
def last_results():
    if 'username' not in session:
        return redirect(url_for('login'))
    # Aqui você pode buscar e exibir os resultados do quiz do banco de dados
    return render_template('last_results.html')

@app.route('/create_quiz', methods=['GET', 'POST'])
def create_quiz():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Recuperar quizzes existentes para exibição
    conn = conectar_bd()
    cursor = conn.cursor()
    cursor.execute('SELECT id, titulo, descricao FROM quizzes')
    quizzes = cursor.fetchall()
    conn.close()
    
    if request.method == 'POST':
        titulo = request.form['titulo']
        descricao = request.form['descricao']
        perguntas = request.form.getlist('perguntas[]')
        respostas = []
        corretas = []
        
        for i in range(len(perguntas)):
            respostas.append(request.form.getlist(f'respostas_{i + 1}[]'))
            corretas.append(request.form.getlist(f'corretas_{i + 1}[]'))
        
        # Obter o ID do usuário logado
        usuario = buscar_usuario_por_username(session['username'])
        usuario_id = usuario[0]

        # Adicionar quiz ao banco de dados
        conn = conectar_bd()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO quizzes (titulo, descricao, criador_id) VALUES (?, ?, ?)', (titulo, descricao, usuario_id))
        quiz_id = cursor.lastrowid

        # Adicionar perguntas e respostas ao banco de dados
        for i in range(len(perguntas)):
            cursor.execute('INSERT INTO perguntas (quiz_id, texto) VALUES (?, ?)', (quiz_id, perguntas[i]))
            pergunta_id = cursor.lastrowid
            for j in range(len(respostas[i])):
                correta = 1 if str(j + 1) in corretas[i] else 0
                cursor.execute('INSERT INTO respostas (pergunta_id, texto, correta) VALUES (?, ?, ?)', (pergunta_id, respostas[i][j], correta))
        
        conn.commit()
        conn.close()
        
        # Atualizar a lista de quizzes após a criação do novo quiz
        conn = conectar_bd()
        cursor = conn.cursor()
        cursor.execute('SELECT id, titulo, descricao FROM quizzes')
        quizzes = cursor.fetchall()
        conn.close()

        return redirect(url_for('home'))
    
    return render_template('create_quiz.html', quizzes=quizzes)

@app.route('/profile_settings', methods=['GET', 'POST'])
def profile_settings():
    if 'username' not in session:
        return redirect(url_for('login'))

    usuario = buscar_usuario_por_username(session['username'])

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Atualizar email e senha (se fornecidos)
        if email:
            usuario = buscar_usuario_por_email(email)
            if usuario:
                error = 'Email já está em uso. Por favor, escolha outro.'
                return render_template('profile_settings.html', user=usuario, error=error)
            conn = conectar_bd()
            cursor = conn.cursor()
            cursor.execute('UPDATE usuarios SET email = ? WHERE username = ?', (email, session['username']))
            conn.commit()
            conn.close()
        
        if password:
            hashed_password = criar_hash_senha(password)
            conn = conectar_bd()
            cursor = conn.cursor()
            cursor.execute('UPDATE usuarios SET senha = ? WHERE username = ?', (hashed_password, session['username']))
            conn.commit()
            conn.close()

        # Atualizar a variável usuario com os novos dados
        usuario = buscar_usuario_por_username(session['username'])

    return render_template('profile_settings.html', user=usuario)


@app.route('/quizzes')
def quizzes():
    conn = conectar_bd()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM quizzes')
    quizzes = cursor.fetchall()
    conn.close()
    return render_template('quizzes.html', quizzes=quizzes)


@app.route('/delete_quiz/<int:quiz_id>', methods=['POST'])
@login_required
def delete_quiz(quiz_id):
    # Lógica para deletar o quiz aqui
    conn = conectar_bd()
    conn.execute('DELETE FROM quizzes WHERE id = ?', (quiz_id,))
    conn.commit()
    conn.close()
    flash('Quiz deletado com sucesso!', 'success')
    return redirect(url_for('quizzes'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# Atualizar a função principal
if __name__ == '__main__':
    criar_tabela_usuarios()
    criar_tabela_quizzes()  # Criar as tabelas de quizzes ao iniciar o aplicativo
    app.run(debug=True)
