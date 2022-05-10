"""
postgresql connection 객체 저장 dict
"""
postgresql = dict()


def get_db(name):
    if name in postgresql:
        return postgresql.get(name)
