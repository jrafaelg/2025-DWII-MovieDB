# Preparando a aplicação

Todas as operações devem ser executadas:
1. Dentro do ambiente virtual da aplicação (abra o "Terminal" no PyCharm que o ambiente virtual devb ser ativado automaticamente)
2. No diretório raiz da aplicação (onde está o arquivo `app.py`)

A migração do banco de dados, agora, está sendo feita pelo Flask-Migrate. Para preparar a aplicação,
você deve seguir os seguintes passos:

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

**Se a sua aplicação já tem migrações criadas, não execute os passos 3, 4 e 5. Apenas execute o passo 6 para aplicar as migrações ao banco de dados.**

Lembre-se de criar um arquivo de configuração adequado ao seu cenário de uso, com base no exemplo fornecido em `config.sample.json`.
