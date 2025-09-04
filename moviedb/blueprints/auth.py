from urllib.parse import urlsplit

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from moviedb.forms.auth import RegistrationForm
from moviedb import db
from moviedb.models.autenticacao import User

bp = Blueprint(name='auth',
               import_name=__name__,
               url_prefix='/auth')


@bp.route('/register', methods=['GET', 'POST'])
def register():
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
