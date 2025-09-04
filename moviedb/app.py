from moviedb import create_app


def run():
    app = create_app()
    app.logger.info("Aplicação iniciada")
    app.run(host=app.config['APP_HOST'],
            port=app.config['APP_PORT'],
            )


if __name__ == "__main__":
    run()
