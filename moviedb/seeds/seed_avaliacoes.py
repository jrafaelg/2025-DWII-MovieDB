#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script para criar avaliações de exemplo no banco de dados.
IMPORTANTE: Execute seed_data.py primeiro e crie alguns usuários na aplicação.

Uso: python seed_avaliacoes.py
"""

import sys
import random
from moviedb import create_app
from moviedb import db
from moviedb.models.filme import Filme
from moviedb.models.autenticacao import User
from moviedb.models.relacoes import Avaliacao


def criar_avaliacoes():
    """Cria avaliações de exemplo para os filmes"""
    print("⭐ Criando avaliações de exemplo...")

    # Buscar todos os filmes
    filmes = list(Filme.get_all())
    if not filmes:
        print("❌ Nenhum filme encontrado. Execute seed_data.py primeiro.")
        return

    # Buscar todos os usuários
    usuarios = list(User.get_all())
    if not usuarios:
        print("❌ Nenhum usuário encontrado. Crie usuários na aplicação primeiro.")
        return

    print(f"Encontrados {len(filmes)} filmes e {len(usuarios)} usuários.")
    print()

    # Perfis de avaliação (para simular diferentes tipos de avaliadores)
    perfis = {
        "critico": {  # Crítico rigoroso
            "notas": [6, 7, 7, 8, 8, 8, 9],
            "recomenda_prob": 0.6
        },
        "entusiasta": {  # Fã de cinema
            "notas": [7, 8, 8, 8, 9, 9, 9, 10],
            "recomenda_prob": 0.85
        },
        "casual": {  # Espectador casual
            "notas": [5, 6, 7, 7, 8, 8, 9],
            "recomenda_prob": 0.7
        }
    }

    avaliacoes_criadas = 0

    for filme in filmes:
        print(f"\n📽️  {filme.titulo_original}")

        # Decidir quantas avaliações este filme terá (entre 50% e 100% dos usuários)
        num_avaliacoes = random.randint(len(usuarios) // 2, len(usuarios))

        # Selecionar usuários aleatórios
        usuarios_avaliar = random.sample(usuarios, num_avaliacoes)

        for usuario in usuarios_avaliar:
            print(f"filme_id {filme.id} usuario_id {usuario.id}")
            # Verificar se já existe avaliação
            avaliacao_existe = Avaliacao.get_by_composed_id({
                "filme_id": filme.id,
                "usuario_id": usuario.id
            })

            if avaliacao_existe:
                continue

            # Escolher perfil aleatório
            perfil = random.choice(list(perfis.values()))

            # Gerar nota baseada no perfil
            nota = random.choice(perfil["notas"])

            # Decidir se recomenda (baseado na probabilidade do perfil)
            recomenda = random.random() < perfil["recomenda_prob"]

            # Comentários opcionais (30% de chance)
            comentario = None
            if random.random() < 0.3:
                comentarios_positivos = [
                    "Filme excepcional! Recomendo muito.",
                    "Uma obra-prima do cinema.",
                    "Adorei cada minuto!",
                    "Performances incríveis dos atores.",
                    "Um dos melhores filmes que já vi.",
                    "História envolvente do início ao fim.",
                    "Fotografia impecável e direção brilhante.",
                ]
                comentarios_neutros = [
                    "Filme interessante, mas esperava mais.",
                    "Tem seus momentos, mas não é perfeito.",
                    "Entretenimento decente.",
                    "Vale a pena assistir uma vez.",
                ]
                comentarios_negativos = [
                    "Não correspondeu às expectativas.",
                    "Um pouco superestimado.",
                    "Bom, mas nada excepcional.",
                ]

                if nota >= 8:
                    comentario = random.choice(comentarios_positivos)
                elif nota >= 6:
                    comentario = random.choice(comentarios_neutros)
                else:
                    comentario = random.choice(comentarios_negativos)

            # Criar avaliação
            avaliacao = Avaliacao(
                filme_id=filme.id,
                usuario_id=usuario.id,
                nota=nota,
                comentario=comentario,
                recomenda=recomenda
            )
            db.session.add(avaliacao)
            avaliacoes_criadas += 1

        # Commit a cada filme
        db.session.commit()
        print(f"  ✓ {num_avaliacoes} avaliações criadas")

    return avaliacoes_criadas


def exibir_estatisticas():
    """Exibe estatísticas das avaliações criadas"""
    print("\n" + "=" * 80)
    print("ESTATÍSTICAS DAS AVALIAÇÕES")
    print("=" * 80 + "\n")

    filmes = list(Filme.get_all())

    for filme in filmes:
        avaliacoes = list(Avaliacao.get_all_by({"filme_id": filme.id}))

        if not avaliacoes:
            continue

        notas = [av.nota for av in avaliacoes]
        nota_media = sum(notas) / len(notas)
        recomendam = sum(1 for av in avaliacoes if av.recomenda)
        percentual = (recomendam / len(avaliacoes)) * 100

        print(f"📽️  {filme.titulo_original}")
        print(f"   Nota média: {nota_media:.1f}/10")
        print(f"   Avaliações: {len(avaliacoes)}")
        print(f"   Recomendam: {percentual:.1f}% ({recomendam}/{len(avaliacoes)})")
        print()


def main():
    """Função principal"""
    print("=" * 80)
    print("SEED DE AVALIAÇÕES - MYMOVIEDB")
    print("=" * 80)
    print()

    # Criar app e contexto
    app = create_app()

    with app.app_context():
        try:
            avaliacoes_criadas = criar_avaliacoes()

            if avaliacoes_criadas and avaliacoes_criadas > 0:
                exibir_estatisticas()

                print("=" * 80)
                print("✅ AVALIAÇÕES CRIADAS COM SUCESSO!")
                print("=" * 80)
                print(f"\nTotal: {avaliacoes_criadas} avaliações")
                print()
            else:
                print("\n⚠️  Nenhuma avaliação foi criada.")
                print("   Certifique-se de que:")
                print("   1. O seed_data.py foi executado")
                print("   2. Existem usuários criados na aplicação")
                print()

        except Exception as e:
            print(f"\n❌ ERRO: {e}")
            db.session.rollback()
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    main()
