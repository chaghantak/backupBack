"""
neo4j connection 객체 저장 dict
"""
neo4j = dict()


def get_db(name):
    if name in neo4j:
        return neo4j.get(name)
