# Preparando a aplicação

A migração do banco de dados, agora, está sendo feita pelo Flask-Migrate. Para preparar a aplicação, você deve seguir os seguintes passos, de dentro do diretório da aplicação:

1. Instale as dependências do projeto:
   ```bash
   pip install -r requirements.txt
   ```
2. Configure a variável de ambiente `FLASK_APP` para apontar para o arquivo principal da aplicação:
   ```bash
   export FLASK_APP=app.py  # No Windows use: set FLASK_APP=app.py
   ```
3. Inicialize o repositório de migrações:
   ```bash
   flask db init
   ```
4. Faça as alterações necessárias no arquivo `migrations/env.py` para configurar o `target_metada` e carregar os modelos da aplicação (por volta da linha 30):
   ```python
   from moviedb import db
   import moviedb.models # noqa: F401
   target_metadata = db.metadata
   ```
5. Crie a primeira migração:
   ```bash
   flask db migrate -m "Migracao inicial"
   ```
6. Aplique a migração ao banco de dados:
   ```bash
   flask db upgrade
   ```
7. Agora, você pode rodar a aplicação:
   ```bash
   flask run
   ```
