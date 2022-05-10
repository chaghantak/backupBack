
"""
mongodb connection 객체 저장 dict
"""
mongo = dict()


def get_db(name):
    if name in mongo:
        return mongo.get(name).db
