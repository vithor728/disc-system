from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, g
import os
import sys
import json
import datetime
import logging
import argparse
from pathlib import Path
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv

# Carregar variáveis de ambiente
load_dotenv()

# Configurar logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from src.models import db, Usuario, Equipe, Colaborador
from src.auth import init_auth, login_required, admin_required, pode_acessar_equipe, pode_acessar_colaborador
from src.auth import criar_usuario_admin_inicial, criar_equipes_iniciais, criar_coordenadores_iniciais

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'disc_app_secret_key')

# Configuração do banco de dados - PostgreSQL para produção, SQLite para desenvolvimento
if os.environ.get('DATABASE_URL'):
    # Configuração para PostgreSQL em produção (Render.com)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    logger.info(f"Usando banco de dados PostgreSQL em produção")
else:
    # Configuração para SQLite em desenvolvimento
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
    os.makedirs(data_dir, exist_ok=True)
    db_path = os.path.join(data_dir, 'disc_app.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    logger.info(f"Usando banco de dados SQLite em desenvolvimento: {db_path}")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar o banco de dados
db.init_app(app)

# Inicializar autenticação
init_auth(app, db)

# Função para criar usuário Victor Lima
def criar_usuario_victor(db):
    """Cria um usuário específico para Victor Lima"""
    if not Usuario.query.filter_by(email='victor.lima@gavresorts.com.br').first():
        logger.info("Criando usuário Victor Lima")
        admin = Usuario(
            nome='Victor Lima',
            email='victor.lima@gavresorts.com.br',
            nivel_acesso='admin'
        )
        admin.set_senha('disc2025')
        logger.debug(f"Senha definida para usuário victor.lima@gavresorts.com.br")
        db.session.add(admin)
        db.session.commit()
        logger.info("Usuário Victor Lima criado")
        return True
    logger.info("Usuário Victor Lima já existe")
    return False

# Função para criar usuário admin simples
def criar_usuario_admin_simples(db):
    """Cria um usuário admin com nome simples"""
    if not Usuario.query.filter_by(nome='admin').first():
        logger.info("Criando usuário admin simples")
        admin = Usuario(
            nome='admin',
            email='admin_simples@exemplo.com',
            nivel_acesso='admin'
        )
        admin.set_senha('disc2025')
        logger.debug(f"Senha definida para usuário admin simples")
        db.session.add(admin)
        db.session.commit()
        logger.info("Usuário admin simples criado")
        return True
    logger.info("Usuário admin simples já existe")
    return False

# Criar tabelas e dados iniciais
with app.app_context():
    db.create_all()
    criar_usuario_admin_inicial(db)
    criar_usuario_victor(db)
    criar_usuario_admin_simples(db)
    criar_equipes_iniciais(db)
    criar_coordenadores_iniciais(db)
    logger.info("Banco de dados inicializado")

# Rotas
@app.route('/')
def index():
    logger.debug("Acessando página inicial")
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Aceitar tanto email quanto nome de usuário
        identificador = request.form.get('identificador')
        senha = request.form.get('senha')
        
        logger.info(f"Tentativa de login com identificador: {identificador}")
        
        # Buscar usuário por email ou nome de usuário
        usuario = Usuario.query.filter(
            (Usuario.email == identificador) | (Usuario.nome == identificador)
        ).first()
        
        if not usuario:
            logger.warning(f"Usuário não encontrado: {identificador}")
            error = 'Credenciais inválidas. Por favor, tente novamente.'
        elif usuario.verificar_senha(senha):
            logger.info(f"Login bem-sucedido: {usuario.email}")
            session['usuario_id'] = usuario.id
            flash(f'Bem-vindo, {usuario.nome}!', 'success')
            return redirect(url_for('admin'))
        else:
            logger.warning(f"Senha incorreta para: {identificador}")
            error = 'Credenciais inválidas. Por favor, tente novamente.'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    logger.debug("Realizando logout")
    session.pop('usuario_id', None)
    flash('Você saiu do sistema.', 'info')
    return redirect(url_for('index'))

@app.route('/questionario', methods=['GET', 'POST'])
def questionario():
    # Buscar todas as equipes para o formulário
    equipes = Equipe.query.all()
    
    if request.method == 'POST':
        # Processar dados do formulário
        nome = request.form.get('nome')
        email = request.form.get('email')
        cargo = request.form.get('cargo')
        equipe_id = request.form.get('equipe_id')
        
        # Validar equipe
        if not equipe_id:
            flash('Por favor, selecione uma equipe.', 'danger')
            return render_template('questionario.html', equipes=equipes)
        
        # Processar respostas do questionário
        respostas = {}
        for i in range(1, 11):  # 10 grupos de perguntas
            grupo_key = f'grupo{i}'
            respostas[grupo_key] = request.form.getlist(grupo_key)
        
        # Calcular pontuações DISC
        pontuacao_d = 0
        pontuacao_i = 0
        pontuacao_s = 0
        pontuacao_c = 0
        
        for grupo, valores in respostas.items():
            for valor in valores:
                if valor == 'D':
                    pontuacao_d += 1
                elif valor == 'I':
                    pontuacao_i += 1
                elif valor == 'S':
                    pontuacao_s += 1
                elif valor == 'C':
                    pontuacao_c += 1
        
        # Determinar perfil predominante e secundário
        pontuacoes = {
            'D': pontuacao_d,
            'I': pontuacao_i,
            'S': pontuacao_s,
            'C': pontuacao_c
        }
        
        perfil_predominante = max(pontuacoes, key=pontuacoes.get)
        
        # Remover o perfil predominante para encontrar o secundário
        pontuacoes_sem_predominante = pontuacoes.copy()
        pontuacoes_sem_predominante.pop(perfil_predominante)
        perfil_secundario = max(pontuacoes_sem_predominante, key=pontuacoes_sem_predominante.get)
        
        # Verificar se já existe um colaborador com este email
        colaborador = Colaborador.query.filter_by(email=email).first()
        
        try:
            if colaborador:
                # Atualizar colaborador existente
                colaborador.nome = nome
                colaborador.cargo = cargo
                colaborador.equipe_id = equipe_id
                colaborador.data_preenchimento = datetime.datetime.utcnow()
                colaborador.pontuacao_d = pontuacao_d
                colaborador.pontuacao_i = pontuacao_i
                colaborador.pontuacao_s = pontuacao_s
                colaborador.pontuacao_c = pontuacao_c
                colaborador.perfil_predominante = perfil_predominante
                colaborador.perfil_secundario = perfil_secundario
                logger.info(f"Colaborador atualizado: {email}")
            else:
                # Criar novo colaborador
                colaborador = Colaborador(
                    nome=nome,
                    email=email,
                    cargo=cargo,
                    equipe_id=equipe_id,
                    pontuacao_d=pontuacao_d,
                    pontuacao_i=pontuacao_i,
                    pontuacao_s=pontuacao_s,
                    pontuacao_c=pontuacao_c,
                    perfil_predominante=perfil_predominante,
                    perfil_secundario=perfil_secundario
                )
                db.session.add(colaborador)
                logger.info(f"Novo colaborador criado: {email}")
            
            # Commit explícito para garantir persistência
            db.session.commit()
            logger.info(f"Dados do colaborador {email} salvos com sucesso")
            
            # Redirecionar para a página de resultados
            return redirect(url_for('resultado', id=colaborador.id))
        except Exception as e:
            # Em caso de erro, fazer rollback e registrar
            db.session.rollback()
            logger.error(f"Erro ao salvar dados do colaborador {email}: {e}")
            flash('Ocorreu um erro ao salvar seus dados. Por favor, tente novamente.', 'danger')
    
    return render_template('questionario.html', equipes=equipes)

@app.route('/resultado/<int:id>')
def resultado(id):
    colaborador = Colaborador.query.get_or_404(id)
    return render_template('resultado.html', colaborador=colaborador)

@app.route('/admin')
@login_required
def admin():
    logger.debug(f"Acessando painel admin por: {g.usuario.email if g.usuario else 'Usuário não logado'}")
    # Se for admin, busca todas as equipes e colaboradores
    # Se for coordenador, busca apenas sua equipe e colaboradores
    if g.usuario.is_admin():
        equipes = Equipe.query.all()
        colaboradores = Colaborador.query.all()
        logger.debug(f"Usuário admin: carregando todas as equipes e colaboradores")
    else:
        equipes = [g.usuario.equipe] if g.usuario.equipe else []
        colaboradores = Colaborador.query.filter_by(equipe_id=g.usuario.equipe_id).all()
        logger.debug(f"Usuário coordenador: carregando equipe {g.usuario.equipe_id}")
    
    return render_template('admin.html', equipes=equipes, colaboradores=colaboradores)

@app.route('/relatorio/<int:id>')
@login_required
def relatorio(id):
    colaborador = Colaborador.query.get_or_404(id)
    
    # Verificar se o usuário tem permissão para acessar este colaborador
    if not pode_acessar_colaborador(colaborador):
        flash('Você não tem permissão para acessar este colaborador.', 'danger')
        return redirect(url_for('admin'))
    
    return render_template('relatorio.html', colaborador=colaborador)

@app.route('/gerenciar_usuarios')
@admin_required
def gerenciar_usuarios():
    usuarios = Usuario.query.all()
    equipes = Equipe.query.all()
    mensagem = request.args.get('mensagem')
    tipo_mensagem = request.args.get('tipo_mensagem', 'info')
    
    return render_template('gerenciar_usuarios.html', 
                          usuarios=usuarios, 
                          equipes=equipes, 
                          mensagem=mensagem, 
                          tipo_mensagem=tipo_mensagem)

@app.route('/criar_usuario', methods=['POST'])
@admin_required
def criar_usuario():
    nome = request.form.get('nome')
    email = request.form.get('email')
    senha = request.form.get('senha')
    nivel_acesso = request.form.get('nivel_acesso')
    equipe_id = request.form.get('equipe_id') if request.form.get('equipe_id') else None
    
    # Validar dados
    if nivel_acesso == 'coordenador' and not equipe_id:
        flash('Coordenadores devem estar associados a uma equipe.', 'danger')
        return redirect(url_for('gerenciar_usuarios'))
    
    # Verificar se email já existe
    if Usuario.query.filter_by(email=email).first():
        flash('Este email já está em uso.', 'danger')
        return redirect(url_for('gerenciar_usuarios'))
    
    try:
        # Criar usuário
        usuario = Usuario(
            nome=nome,
            email=email,
            nivel_acesso=nivel_acesso,
            equipe_id=equipe_id
        )
        usuario.set_senha(senha)
        
        db.session.add(usuario)
        db.session.commit()
        logger.info(f"Usuário {nome} criado com sucesso")
        
        flash(f'Usuário {nome} criado com sucesso!', 'success')
        return redirect(url_for('gerenciar_usuarios'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao criar usuário {nome}: {e}")
        flash(f'Erro ao criar usuário: {str(e)}', 'danger')
        return redirect(url_for('gerenciar_usuarios'))

@app.route('/atualizar_usuario', methods=['POST'])
@admin_required
def atualizar_usuario():
    id = request.form.get('id')
    nome = request.form.get('nome')
    email = request.form.get('email')
    nivel_acesso = request.form.get('nivel_acesso')
    equipe_id = request.form.get('equipe_id') if request.form.get('equipe_id') else None
    
    # Validar dados
    if nivel_acesso == 'coordenador' and not equipe_id:
        flash('Coordenadores devem estar associados a uma equipe.', 'danger')
        return redirect(url_for('gerenciar_usuarios'))
    
    # Buscar usuário
    usuario = Usuario.query.get_or_404(id)
    
    # Verificar se email já existe (exceto para o próprio usuário)
    email_existente = Usuario.query.filter_by(email=email).first()
    if email_existente and email_existente.id != int(id):
        flash('Este email já está em uso.', 'danger')
        return redirect(url_for('gerenciar_usuarios'))
    
    try:
        # Atualizar usuário
        usuario.nome = nome
        usuario.email = email
        usuario.nivel_acesso = nivel_acesso
        usuario.equipe_id = equipe_id
        
        db.session.commit()
        logger.info(f"Usuário {nome} atualizado com sucesso")
        
        flash(f'Usuário {nome} atualizado com sucesso!', 'success')
        return redirect(url_for('gerenciar_usuarios'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao atualizar usuário {nome}: {e}")
        flash(f'Erro ao atualizar usuário: {str(e)}', 'danger')
        return redirect(url_for('gerenciar_usuarios'))

@app.route('/resetar_senha', methods=['POST'])
@admin_required
def resetar_senha():
    id = request.form.get('id')
    nova_senha = request.form.get('nova_senha')
    confirmar_senha = request.form.get('confirmar_senha')
    
    # Validar senhas
    if nova_senha != confirmar_senha:
        flash('As senhas não coincidem.', 'danger')
        return redirect(url_for('gerenciar_usuarios'))
    
    # Buscar usuário
    usuario = Usuario.query.get_or_404(id)
    
    try:
        # Resetar senha
        usuario.set_senha(nova_senha)
        db.session.commit()
        logger.info(f"Senha do usuário {usuario.nome} resetada com sucesso")
        
        flash(f'Senha do usuário {usuario.nome} resetada com sucesso!', 'success')
        return redirect(url_for('gerenciar_usuarios'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao resetar senha do usuário {usuario.nome}: {e}")
        flash(f'Erro ao resetar senha: {str(e)}', 'danger')
        return redirect(url_for('gerenciar_usuarios'))

@app.route('/excluir_usuario', methods=['POST'])
@admin_required
def excluir_usuario():
    id = request.form.get('id')
    
    # Não permitir excluir o próprio usuário
    if int(id) == g.usuario.id:
        flash('Você não pode excluir seu próprio usuário.', 'danger')
        return redirect(url_for('gerenciar_usuarios'))
    
    # Buscar usuário
    usuario = Usuario.query.get_or_404(id)
    
    try:
        # Excluir usuário
        db.session.delete(usuario)
        db.session.commit()
        logger.info(f"Usuário {usuario.nome} excluído com sucesso")
        
        flash(f'Usuário {usuario.nome} excluído com sucesso!', 'success')
        return redirect(url_for('gerenciar_usuarios'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao excluir usuário {usuario.nome}: {e}")
        flash(f'Erro ao excluir usuário: {str(e)}', 'danger')
        return redirect(url_for('gerenciar_usuarios'))

@app.route('/gerenciar_equipes')
@admin_required
def gerenciar_equipes():
    equipes = Equipe.query.all()
    mensagem = request.args.get('mensagem')
    tipo_mensagem = request.args.get('tipo_mensagem', 'info')
    
    return render_template('gerenciar_equipes.html', 
                          equipes=equipes, 
                          mensagem=mensagem, 
                          tipo_mensagem=tipo_mensagem)

@app.route('/criar_equipe', methods=['POST'])
@admin_required
def criar_equipe():
    nome = request.form.get('nome')
    descricao = request.form.get('descricao')
    
    # Verificar se nome já existe
    if Equipe.query.filter_by(nome=nome).first():
        flash('Já existe uma equipe com este nome.', 'danger')
        return redirect(url_for('gerenciar_equipes'))
    
    try:
        # Criar equipe
        equipe = Equipe(
            nome=nome,
            descricao=descricao
        )
        
        db.session.add(equipe)
        db.session.commit()
        logger.info(f"Equipe {nome} criada com sucesso")
        
        flash(f'Equipe {nome} criada com sucesso!', 'success')
        return redirect(url_for('gerenciar_equipes'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao criar equipe {nome}: {e}")
        flash(f'Erro ao criar equipe: {str(e)}', 'danger')
        return redirect(url_for('gerenciar_equipes'))

@app.route('/atualizar_equipe', methods=['POST'])
@admin_required
def atualizar_equipe():
    id = request.form.get('id')
    nome = request.form.get('nome')
    descricao = request.form.get('descricao')
    
    # Buscar equipe
    equipe = Equipe.query.get_or_404(id)
    
    # Verificar se nome já existe (exceto para a própria equipe)
    nome_existente = Equipe.query.filter_by(nome=nome).first()
    if nome_existente and nome_existente.id != int(id):
        flash('Já existe uma equipe com este nome.', 'danger')
        return redirect(url_for('gerenciar_equipes'))
    
    try:
        # Atualizar equipe
        equipe.nome = nome
        equipe.descricao = descricao
        
        db.session.commit()
        logger.info(f"Equipe {nome} atualizada com sucesso")
        
        flash(f'Equipe {nome} atualizada com sucesso!', 'success')
        return redirect(url_for('gerenciar_equipes'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao atualizar equipe {nome}: {e}")
        flash(f'Erro ao atualizar equipe: {str(e)}', 'danger')
        return redirect(url_for('gerenciar_equipes'))

@app.route('/excluir_equipe', methods=['POST'])
@admin_required
def excluir_equipe():
    id = request.form.get('id')
    
    # Buscar equipe
    equipe = Equipe.query.get_or_404(id)
    
    try:
        # Verificar se há colaboradores associados
        colaboradores = Colaborador.query.filter_by(equipe_id=id).all()
        for colaborador in colaboradores:
            db.session.delete(colaborador)
        
        # Verificar se há usuários associados
        usuarios = Usuario.query.filter_by(equipe_id=id).all()
        for usuario in usuarios:
            usuario.equipe_id = None
        
        # Excluir equipe
        db.session.delete(equipe)
        db.session.commit()
        logger.info(f"Equipe {equipe.nome} excluída com sucesso")
        
        flash(f'Equipe {equipe.nome} excluída com sucesso!', 'success')
        return redirect(url_for('gerenciar_equipes'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erro ao excluir equipe {equipe.nome}: {e}")
        flash(f'Erro ao excluir equipe: {str(e)}', 'danger')
        return redirect(url_for('gerenciar_equipes'))

@app.route('/exportar_csv')
@login_required
def exportar_csv():
    import csv
    from io import StringIO
    from flask import Response
    
    # Se for admin, exporta todos os colaboradores
    # Se for coordenador, exporta apenas colaboradores da sua equipe
    if g.usuario.is_admin():
        colaboradores = Colaborador.query.all()
    else:
        colaboradores = Colaborador.query.filter_by(equipe_id=g.usuario.equipe_id).all()
    
    # Criar CSV
    output = StringIO()
    writer = csv.writer(output)
    
    # Cabeçalho
    writer.writerow(['Nome', 'Email', 'Cargo', 'Equipe', 'Data Preenchimento', 
                    'Perfil Predominante', 'Perfil Secundário', 
                    'Pontuação D', 'Pontuação I', 'Pontuação S', 'Pontuação C'])
    
    # Dados
    for c in colaboradores:
        writer.writerow([
            c.nome,
            c.email,
            c.cargo,
            c.equipe.nome if c.equipe else '',
            c.data_preenchimento.strftime('%d/%m/%Y %H:%M') if c.data_preenchimento else '',
            c.perfil_predominante,
            c.perfil_secundario,
            c.pontuacao_d,
            c.pontuacao_i,
            c.pontuacao_s,
            c.pontuacao_c
        ])
    
    # Criar resposta
    response = Response(output.getvalue(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=colaboradores_disc.csv'
    
    return response

@app.route('/status_db')
@admin_required
def status_db():
    try:
        # Contar registros
        with app.app_context():
            num_usuarios = Usuario.query.count()
            num_equipes = Equipe.query.count()
            num_colaboradores = Colaborador.query.count()
        
        # Informações sobre o banco de dados
        db_info = {
            'tipo': 'PostgreSQL' if os.environ.get('DATABASE_URL') else 'SQLite',
            'url': os.environ.get('DATABASE_URL', app.config['SQLALCHEMY_DATABASE_URI'])
        }
        
        return render_template('status_db.html', 
                              db_info=db_info,
                              num_usuarios=num_usuarios,
                              num_equipes=num_equipes,
                              num_colaboradores=num_colaboradores)
    except Exception as e:
        flash(f'Erro ao verificar status do banco de dados: {str(e)}', 'danger')
        return redirect(url_for('admin'))

# Configuração para Gunicorn
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Executar aplicação Flask DISC')
    parser.add_argument('--port', type=int, default=5000, help='Porta para executar a aplicação')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host para executar a aplicação')
    args = parser.parse_args()
    
    app.run(host=args.host, port=args.port, debug=True)
