from flask import Blueprint

from forms.filme import AddForm
from models import Filme

bp = Blueprint(name='filme',
               import_name=__name__,
               url_prefix='/auth')

@bp.route('/filme', methods=['GET', 'POST'])
def filme():
    pass

@bp.route('/add', methods=['GET', 'POST'])
def add():

    form = AddForm()

    if form.validate_on_submit():
        filme = Filme()
        filme.nome = form.nome.data
        filme.email = form.email.data
        filme.ativo = False
        filme.password = form.password.data
        db.session.add(filme)
        # Realiza o flush para garantir que o usuário tenha um ID gerado antes do commit.
        db.session.flush()
        # Atualiza o objeto usuário com os dados mais recentes do banco de dados.
        db.session.refresh(usuario)
        token = create_jwt_token(action=JWT_action.VALIDAR_EMAIL, sub=usuario.email)
        current_app.logger.debug("Token de validação de email: %s" % (token,))
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

