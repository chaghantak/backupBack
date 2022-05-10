from flask_restx import Namespace, fields


class ChainDto:
    """
    Api 객체 각 namespace 와 해당 api 에서 사용 하는 model 객체를 정의
    """
    api = Namespace('chain', description='Chain Rest Api')

    """
    events_new 테이블 쿼리 할때 사용할 model 객체
    """
    events_search = api.model('Chain Events Search', {
        'host': fields.String(required=False),
        'startTime': fields.String(required=False),
        'endTime': fields.String(required=False)
    })

    """
    events_new 테이블 mitre_attack_ttp 값으로 조회 할때 사용할 model 객체
    """
    ttp_search = api.model('Ttp Events Search', {
        'ttp': fields.String,
        'host': fields.String(required=False)
    })

    """
    events_new 테이블 _id 및 neo4j chain DB id 값으로 조회 할때 사용할 model 객체
    """
    id_search = api.model('Id Events Search', {
        'id': fields.String(required=False)
    })

    """
    test model
    """

    test_search = api.model('Test Events Search', {
        'id': fields.String(required=False)
    })

