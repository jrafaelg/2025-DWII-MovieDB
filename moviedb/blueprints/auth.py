from urllib.parse import urlsplit

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from moviedb import db
from moviedb.forms.auth import AskToResetPasswordForm, LoginForm, RegistrationForm, \
    SetNewPasswordForm
from moviedb.infra.tokens import create_jwt_token, verify_jwt_token
from moviedb.models.autenticacao import normalizar_email, User
from moviedb.models.enumeracoes import JWT_action

bp = Blueprint(name='auth',
               import_name=__name__,
               url_prefix='/auth')


@bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    Exibe o formulário de registro de usuário e processa o cadastro.

    - Usuários já autenticados não podem acessar esta rota.
    - Se o formulário for enviado e validado, cria um novo usuário,
      salva no banco de dados, envia um email de confirmação e
      redireciona para a página inicial.
    - O usuário deve confirmar o email antes de conseguir logar.
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
        usuario.nome = form.nome.data
        usuario.email = form.email.data
        usuario.ativo = False
        usuario.password = form.password.data
        db.session.add(usuario)
        # Realiza o flush para garantir que o usuário tenha um ID gerado antes do commit.
        db.session.flush()
        # Atualiza o objeto usuário com os dados mais recentes do banco de dados.
        db.session.refresh(usuario)
        token = create_jwt_token(action=JWT_action.VALIDAR_EMAIL, sub=usuario.email)
        current_app.logger.debug("Token de validação de email: %s", token)
        body = render_template('auth/email_confirmation.jinja2',
                               nome=usuario.nome,
                               url=url_for('auth.valida_email', token=token))
        if not usuario.send_email(subject="Confirme o seu email", body=body):
            flash("Erro no envio do email de confirmação da conta", category="danger")
        db.session.commit()
        flash("Cadastro efetuado com sucesso. Confirme o seu email antes de logar "
              "no sistema", category='success')
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


@bp.route('/valida_email/<token>')
def valida_email(token):
    """
    Valida o email do usuário a partir de um token JWT.

    - Usuários autenticados não podem acessar esta rota.
    - O token é verificado e deve conter as claims 'sub' (email) e 'action' igual a
    'validate_email'.
    - Se o usuário existir, estiver inativo e o token for válido, ativa o usuário e exibe
    mensagem de sucesso.
    - Em caso de token inválido ou usuário já ativo, exibe mensagem de erro.

    Args:
        token (str): Token JWT enviado na URL para validação do email.

    Returns:
        Response: Redireciona para a página de login ou inicial, conforme o caso.
    """
    if current_user.is_authenticated:
        flash("Acesso não autorizado para usuários logados no sistema", category='warning')
        return redirect(request.referrer if request.referrer else url_for('root.index'))

    claims = verify_jwt_token(token)
    if not (claims.get('valid', False) and {'sub', 'action'}.issubset(claims)):
        flash("Token incorreto ou incompleto", category='warning')
        return redirect(url_for('root.index'))

    usuario = User.get_by_email(claims.get('sub'))
    if (usuario is not None and
            not usuario.ativo and
            claims.get('action') == JWT_action.VALIDAR_EMAIL):
        usuario.ativo = True
        flash(f"Email {usuario.email} validado!", category='success')
        db.session.commit()
        return redirect(url_for('auth.login'))
    flash("Token inválido", category='warning')
    return redirect(url_for('auth.login'))


@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        flash("Acesso não autorizado para usuários logados no sistema", category='warning')
        return redirect(request.referrer if request.referrer else url_for('root.index'))

    claims = verify_jwt_token(token)
    if not (claims.get('valid', False) and {'sub', 'action'}.issubset(claims)):
        flash("Token incorreto ou incompleto", category='warning')
        return redirect(url_for('root.index'))
    usuario = User.get_by_email(claims.get('sub'))
    if usuario is not None and claims.get('action') == JWT_action.RESET_PASSWORD:
        form = SetNewPasswordForm()
        if form.validate_on_submit():
            usuario.password = form.password.data
            db.session.commit()
            flash("Sua senha foi redefinida com sucesso", category='success')
            return redirect(url_for('auth.login'))
        return render_template('auth/simple_form.jinja2',
                               title_card="Escolha uma nova senha",
                               form=form)
    # token não é de reset_password ou é para um usuário inexistente
    flash("Token inválido", category='warning')
    return redirect(url_for('root.index'))


@bp.route('/new_password', methods=['GET', 'POST'])
def new_password():
    if current_user.is_authenticated:
        flash("Acesso não autorizado para usuários logados no sistema", category='warning')
        return redirect(request.referrer if request.referrer else url_for('index'))

    form = AskToResetPasswordForm()
    if form.validate_on_submit():
        email = normalizar_email(form.email.data)
        usuario = User.get_by_email(email)
        flash(f"Se houver uma conta com o email {email}, uma mensagem será enviada com as "
              f"instruções para a troca da senha", category='info')
        if usuario is not None:
            token = create_jwt_token(JWT_action.RESET_PASSWORD,
                                     sub=usuario.email)
            body = render_template('auth/email_new_password.jinja2',
                                   nome=usuario.nome,
                                   url=url_for('auth.reset_password', token=token))
            usuario.send_email(subject="Altere a sua senha", body=body)
            return redirect(url_for('auth.login'))
        current_app.logger.warning("Pedido de reset de senha para usuário inexistente (%s)",
                                   email)
        return redirect(url_for('auth.login'))
    return render_template('auth/simple_form.jinja2',
                           title="Esqueci minha senha",
                           title_card="Esqueci minha senha",
                           subtitle_card="Digite o seu email cadastrado no sistema para "
                                         "solicitar uma nova senha",
                           form=form)
