from urllib.parse import urlsplit

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from moviedb.forms.auth import LoginForm, RegistrationForm
from moviedb import db
from moviedb.models.autenticacao import User

bp = Blueprint(name='auth',
               import_name=__name__,
               url_prefix='/auth')


@bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    Exibe o formulário de registro de usuário e processa o cadastro.

    - Usuários já autenticados não podem acessar esta rota.
    - Se o formulário for enviado e validado, cria um novo usuário,
      salva no banco de dados e redireciona para a página inicial.
    - Caso contrário, renderiza o template de registro.

    Returns:
        Response: Redireciona ou renderiza o template de registro.
    """
    if current_user.is_authenticated:
        flash("Acesso não autorizado para usuários logados no sistema", category='warning')
        return redirect(request.referrer if request.referrer else url_for('index'))

    form = RegistrationForm()
    if form.validate_on_submit():
        usuario = User()
        usuario.nome=form.nome.data
        usuario.email=form.email.data
        usuario.ativo=True
        usuario.password=form.password.data
        db.session.add(usuario)
        db.session.commit()
        flash("Cadastro efetuado com sucesso!", category='success')
        return redirect(url_for('root.index'))

    return render_template('auth/register.jinja2',
                           title="Cadastrar um novo usuário",
                           form=form)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Exibe o formulário de login e processa a autenticação do usuário.

    - Usuários já autenticados não podem acessar esta rota.
    - Se o formulário for enviado e validado, verifica as credenciais do usuário.
    - Se o usuário existir, estiver ativo e a senha estiver correta, realiza o login.
    - Redireciona para a página desejada ou para a página inicial.
    - Caso contrário, exibe mensagens de erro e permanece na página de login.

    Returns:
        Response: Redireciona ou renderiza o template de login.
    """
    if current_user.is_authenticated:
        flash("Acesso não autorizado para usuários logados no sistema", category='warning')
        return redirect(request.referrer if request.referrer else url_for('index'))

    form = LoginForm()

    if form.validate_on_submit():
        usuario = User.get_by_email(form.email.data)

        if usuario is None or not usuario.check_password(form.password.data):
            flash("Email ou senha incorretos", category='warning')
            return redirect(url_for('auth.login'))
        if not usuario.ativo:
            flash("Usuário está impedido de acessar o sistema. Procure um adminstrador",
                  category='danger')
            return redirect(url_for('auth.login'))
        login_user(usuario, remember=form.remember_me.data)
        db.session.commit()
        flash(f"Usuario {usuario.email} logado", category='success')
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('root.index')
        return redirect(next_page)

    return render_template('auth/login.jinja2',
                           title="Login",
                           form=form)


@bp.route('/logout')
@login_required
def logout():
    """
    Realiza o logout do usuário autenticado.

    - Encerra a sessão do usuário.
    - Exibe uma mensagem de sucesso.
    - Redireciona para a página inicial.

    Returns:
        Response: Redireciona para a página inicial após logout.
    """
    logout_user()
    flash("Logout efetuado com sucesso!", category='success')
    return redirect(url_for('root.index'))
