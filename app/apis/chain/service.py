from flask import jsonify
from database.mongo import get_db
from database.neo4j import get_db as get_neo4j
from bson.json_util import dumps
import json

from .util import *
from app.apis.consts import ChainCollection

chain_db = get_db('chain')
neo4j_db = get_neo4j('chain')


class ChainService:
    @staticmethod
    def get_events(params):
        """
        mongodb chain DB 의 events_new 라는 컬렉션 을 조회 하는 함수
        검색 방법
        {"host.ip": "192.168.37.211"}
        {"timestamp":{$gte: "2016-03-07 11:33:48", $lt: "2016-03-07 11:34:48"}}
        :param params: host, startTime, endTime
        :return:
        """
        # 안 가져올 컬럼 정보
        set_column = {
            '@timestamp': False, 'agent': False, 'ecs': False, 'event': False, 'hash': False,
            'log': False, 'message': False, 'next': False, 'prev': False, 'process': False,
            'related': False, 'rule': False, 'user': False, 'winlog': False
        }
        query_str = dict()
        if params is not None:
            add_mongo_query(params, query_str)

        event_results = list(chain_db[ChainCollection.APT291_EVENTS].find(query_str, set_column))

        threats = {}
        for item in event_results:
            item_dict = json.loads(dumps(item))

            event_id = item_dict['_id']

            # tactic, technique, subtechnique 정보를 다 가지고 있음
            threat = item_dict['threat']

            process_threat(event_id, threat, threats)

        result = changeDictFromDict(threats)

        result = sorted_tactic(result)

        return jsonify({'result': 'success', 'items': result})

    @staticmethod
    def get_events_ttp(params):
        if 'ttp' in params and params['ttp'] != '':
            # 안 가져올 컬럼 정보
            set_column = {
                '@timestamp': False, 'agent': False, 'ecs': False, 'event': False, 'hash': False,
                'log': False, 'message': False, 'next': False, 'prev': False, 'process': False,
                'related': False, 'user': False, 'winlog': False, 'threat': False, 'after_es_timestamp': False,
                'alert_timestamp': False, 'before_es_timestamp': False
            }

            query_str = dict()

            add_mongo_query(params, query_str)

            # timestamp 정렬
            event_results = list(chain_db[ChainCollection.APT291_EVENTS].find(query_str, set_column).sort('timestamp', 1))

            events = []
            for item in event_results:
                item_dict = json.loads(dumps(item))

                parse_ttp_event(item_dict, events)

            result = changeDictFromArray(events)

            return jsonify({'result': 'success', 'items': result})
        else:
            return jsonify({'result': 'error', 'message': '검색 요소(ttp)가 없습니다.'})

    @staticmethod
    def get_events_id(params):
        if 'id' in params and params['id'] != '':
            # 안 가져올 컬럼 정보
            set_column = {
                '@timestamp': False, 'agent': False, 'ecs': False, 'hash': False,
                'log': False, 'message': False, 'next': False, 'prev': False,
                'threat': False, 'after_es_timestamp': False,
                'alert_timestamp': False, 'before_es_timestamp': False
            }

            query_str = dict()

            add_mongo_query(params, query_str)

            event_result = list(chain_db[ChainCollection.APT291_EVENTS].find(query_str, set_column))

            if len(event_result) == 1:
                return jsonify({'result': 'success', 'items': parse_event(json.loads(dumps(event_result[0])))})
            else:
                return jsonify({'result': 'success', 'items': []})
        else:
            return jsonify({'result': 'error', 'message': '검색 요소(id) 가 없습니다.'})

    @staticmethod
    def get_neo_chain_id(params):
        if 'id' in params and params['id'] != '':
            event_id = params['id']

            # with neo4j_chain_db.session() as session:
            #    nodes = session.run("match (m)-[:related]->(n:Event) return m, n")

            #        for node in nodes:
            #           print(node)
            with neo4j_db.session() as session:
                query = "MATCH (n)-[r]->(m) WHERE n.id='{event_id}' RETURN *"
                # query = f"MATCH (m)-[r:related] -> (n:Event) RETURN m, r"
                nodes = session.run(query)

                result = []

                for node in nodes.data():
                    result.append(node)

                if len(result) > 0:
                    return jsonify({'result': 'success', 'items': result})
                else:
                    return jsonify({'result': 'success', 'items': []})
        else:
            return jsonify({'result': 'error', 'message': '검색 요소(id) 가 없습니다.'})

    @staticmethod
    def get_test_chain_id(params):
        # 안 가져올 컬럼 정보
        set_column = {
            'prev': False
        }
        query_str = dict()
        if params is not None:
            add_mongo_query(params, query_str)

        event_results = list(chain_db['apt292'].find(query_str, set_column))

        threats = {}
        for item in event_results:
            item_dict = json.loads(dumps(item))

            event_id = item_dict['_id']

            # tactic, technique, subtechnique 정보를 다 가지고 있음
            threat = item_dict['threat']

            process_threat(event_id, threat, threats)

        result = changeDictFromDict(threats)

        result = sorted_tactic(result)

        return jsonify({'result': 'success', 'test': result})

