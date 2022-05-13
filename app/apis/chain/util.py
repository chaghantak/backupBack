import re

from .model import Tactic, Technique, SubTechnique, TtpEvent
from typing import List

from app.apis.consts import *


class TacticCollection:
    navigator = {
        "reconnaissance": 1,
        "resource development": 2,
        "initial access": 3,
        "execution": 4,
        "persistence": 5,
        "privilege escalation": 6,
        "defense evasion": 7,
        "credential access": 8,
        "discovery": 9,
        "lateral movement": 10,
        "collection": 11,
        "command and control": 12,
        "exfiltration": 13,
        "impact": 14,
    }


def process_threat(event_id: str, threat: dict, threats: dict):
    """
    event 테이블 정보 중 threat 항목을 파싱 하여 tactic 트리 구조를 만드는 함수
    :param event_id:
    :param threat:
    :param threats:
    :return:
    """
    if isinstance(threat, list):
        for item in threat:
            parse_tactic(event_id, item, threats)
    elif isinstance(threat, dict):
        parse_tactic(event_id, threat, threats)


def parse_tactic(event_id: str, item: dict, threats: dict):
    """
    tactic 내용을 파싱 하는 함수
    :param event_id:
    :param item:
    :param threats:
    :return:
    """
    if 'tactic' in item:
        tactic = item.get('tactic')
        techniques = item.get('technique')
        tactic_id = tactic.get('id')

        if tactic_id in threats:
            tactic_object = threats.get(tactic_id)
        else:
            tactic_object = Tactic(tactic_id, tactic.get('name'))
            threats[tactic_id] = tactic_object

        for technique in techniques:
            parse_technique(event_id, technique, tactic_object)


def parse_technique(event_id: str, item: dict, tactic: Tactic):
    """
    technique 내용을 파싱 하는 함수
    sub technique 정보가 없을 경우 해당 객체에 event id 정보를 저장 한다
    :param event_id:
    :param item:
    :param tactic:
    :return:
    """
    technique_id = item.get('id')

    # 같은 id 값의 객체가 등록 되어 있으면 가져 와서 사용
    if technique_id in tactic.techniques:
        technique_object = tactic.techniques.get(technique_id)
    else:
        technique_object = Technique(technique_id, item.get('name'))

    subtechniques = item.get('subtechnique')
    if len(subtechniques) > 0:
        for sub in item.get('subtechnique'):
            parse_subtechnique(event_id, sub, technique_object)
    else:
        technique_object.events = event_id

    tactic.techniques = technique_id, technique_object


def parse_subtechnique(event_id: str, item: dict, technique: Technique):
    """
    sub technique 내용을 파싱 하는 함수
    event id 정보를 저장 한다
    :param event_id:
    :param item:
    :param technique:
    :return:
    """
    subtechnique_id = item.get('id')
    if subtechnique_id in technique.subTechniques:
        subtechnique_object = technique.subTechniques.get(subtechnique_id)
    else:
        subtechnique_object = SubTechnique(subtechnique_id, item.get('name'))

    subtechnique_object.events = event_id

    technique.subTechniques = subtechnique_id, subtechnique_object


def parse_ttp_event(item: dict, events: List[TtpEvent]):
    event_id = item['_id']
    event_index = item['_index']
    event_rule = item[KeyConst.RULE]
    event_timestamp = item['timestamp']['$date']
    event_name = ''
    if 'name' in event_rule:
        event_name = event_rule['name']

    event_ips = ''
    if event_index == IndexConst.FILE_BEAT:
        if KeyConst.DESTINATION in item:
            event_ips = item[KeyConst.DESTINATION].get('ip')
        elif KeyConst.SOURCE in item:
            event_ips = item[KeyConst.SOURCE].get('ip')
    else:
        event_ips = item[KeyConst.HOST].get('ip')

    event_ip = ''
    if isinstance(event_ips, list) and len(event_ips) == 2:
        for ip in event_ips:
            if isIpPattern(ip) is not None:
                event_ip = ip
    else:
        event_ip = event_ips

    events.append(TtpEvent(key=event_id, index=event_index, timestamp=event_timestamp, ip=event_ip, name=event_name))


def changeDictFromDict(threats: dict):
    result = []
    # key 오름 차순 정렬
    sorted_dict = sorted(threats.items())
    for value in sorted_dict:
        result.append(value[1].get_dict())

    return result


def changeDictFromArray(array: List[TtpEvent]):
    result = []
    for value in array:
        result.append(value.get_dict())

    return result


def isIpPattern(ip: str):
    p = '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'

    return re.search(p, ip)


def get_dict_info(item: dict, args) -> dict:
    if len(args) == 0:
        return item
    else:
        result = dict()
        for arg in args:
            if item.__contains__(arg):
                result[arg] = item.get(arg)

        return result


def set_event_info_by_key(item: dict, result: dict, key: str, fields: [] = []):
    if item.__contains__(key):
        result[key] = get_dict_info(item.get(key), fields)


def parse_winlogbeat(item: dict, result: dict):
    item_event: dict = item.get('event')
    item_event_category = item_event.get('category')
    item_event_type = item_event.get('type')
    item_event_code = item_event.get('code')
    item_event_action = item_event.get('action')
    item_event_provider = item_event.get('provider')

    if item_event_category is None and item_event_type is None:
        """
        category 와 type 이 없을 경우
        """
        set_event_info_by_key(item, result, KeyConst.EVENT)    # Event
        if item_event_code == EventCodeConst.CODE_5140:
            set_event_info_by_key(item, result, KeyConst.SOURCE)
            set_event_info_by_key(item, result, KeyConst.HOST)
            set_event_info_by_key(item, result, KeyConst.PROCESS)  # process
        elif item_event_code == EventCodeConst.CODE_21:
            set_event_info_by_key(item, result, KeyConst.FILE)
            set_event_info_by_key(item, result, KeyConst.HOST)
            set_event_info_by_key(item, result, KeyConst.USER)
            set_event_info_by_key(item, result, KeyConst.PROCESS)  # process
    elif EventCategoryConst.PROCESS in item_event_category and len(item_event_category):
        """
        category == process and category length == 1
        """
        set_event_info_by_key(item, result, KeyConst.EVENT)    # Event
        if (EventTypeConst.START and EventTypeConst.ACCESS and EventTypeConst.END) in item_event_type:
            set_event_info_by_key(item, result, KeyConst.HOST)
            set_event_info_by_key(item, result, KeyConst.PROCESS)  # process
        elif EventTypeConst.INFO in item_event_type:
            set_event_info_by_key(item, result, KeyConst.HOST)
            set_event_info_by_key(item, result, KeyConst.FILE)
        elif EventTypeConst.CHANGE in item_event_type:
            set_event_info_by_key(item, result, KeyConst.HOST)
            set_event_info_by_key(item, result, KeyConst.FILE)
            set_event_info_by_key(item, result, KeyConst.PROCESS)
            set_event_info_by_key(item, result, KeyConst.WINLOG, ['user'])
    elif EventCategoryConst.NETWORK in item_event_category and len(item_event_category):
        set_event_info_by_key(item, result, KeyConst.EVENT)    # Event
        set_event_info_by_key(item, result, KeyConst.HOST)  # Host
        set_event_info_by_key(item, result, KeyConst.PROCESS)  # process
        if EventTypeConst.START in item_event_type and len(item_event_type) == 3:
            set_event_info_by_key(item, result, KeyConst.DESTINATION)
            set_event_info_by_key(item, result, KeyConst.NETWORK)
            set_event_info_by_key(item, result, KeyConst.SOURCE)
        elif EventTypeConst.INFO in item_event_type and len(item_event_type) == 3:
            set_event_info_by_key(item, result, KeyConst.FILE)
    elif EventCategoryConst.FILE in item_event_category and len(item_event_category) == 1:
        set_event_info_by_key(item, result, KeyConst.EVENT)  # Event
        set_event_info_by_key(item, result, KeyConst.HOST)
        set_event_info_by_key(item, result, KeyConst.PROCESS)  # process
        set_event_info_by_key(item, result, KeyConst.FILE)
    elif EventCategoryConst.REGISTRY in item_event_category and len(item_event_category):
        set_event_info_by_key(item, result, KeyConst.EVENT)  # Event
        set_event_info_by_key(item, result, KeyConst.HOST)
        set_event_info_by_key(item, result, KeyConst.PROCESS)  # process
        set_event_info_by_key(item, result, KeyConst.REGISTRY)
    elif EventCategoryConst.AUTHENTICATION in item_event_category:
        set_event_info_by_key(item, result, KeyConst.EVENT)  # Event
        set_event_info_by_key(item, result, KeyConst.HOST)
        set_event_info_by_key(item, result, KeyConst.PROCESS)  # process
        if EventCodeConst.CODE_4624 == item_event_code:
            set_event_info_by_key(item, result, KeyConst.SOURCE)
    elif (EventCategoryConst.SERVICE and EventCategoryConst.SCHEDULED) in item_event_category:
        set_event_info_by_key(item, result, KeyConst.EVENT)  # Event
        set_event_info_by_key(item, result, KeyConst.HOST)

    event = dict()

    if item_event_category is not None:
        event['category'] = item_event_category
    if item_event_type is not None:
        event['type'] = item_event_type
    if item_event_code is not None:
        event['code'] = item_event_code
    if item_event_action is not None:
        event['action'] = item_event_action
    if item_event_provider is not None:
        event['provider'] = item_event_provider

    result['event'] = event


def parse_filebeat(item: dict, result: dict):
    item_event: dict = item.get(KeyConst.EVENT)
    item_event_category = item_event.get('category')
    item_event_type = item_event.get('type')
    set_event_info_by_key(item, result, KeyConst.EVENT)  # Event
    set_event_info_by_key(item, result, KeyConst.HOST)
    set_event_info_by_key(item, result, KeyConst.SOURCE)
    set_event_info_by_key(item, result, KeyConst.DESTINATION)
    # if len(item_event_category) == 1:
    #     if EventCategoryConst.INTRUSION_DETECTION in item_event_category and EventTypeConst.INFO in item_event_type:
    #         set_event_info_by_key(item, result, KeyConst.DESTINATION)
    #         set_event_info_by_key(item, result, KeyConst.SOURCE)
    #         set_event_info_by_key(item, result, KeyConst.EVENT)  # Event
    #         set_event_info_by_key(item, result, KeyConst.HOST)
    #     if EventCategoryConst.NETWORK in item_event_category:
    #         """
    #         type == protocol or type == connection or (type == protocol and type == info)
    #         or (type == connection and type == info) or (type == connection and type == end)
    #         or (type == connection and type == protocol and type == info)
    #         위 조건 공통 으로 적용
    #         """
    #         set_event_info_by_key(item, result, KeyConst.DESTINATION)
    #         set_event_info_by_key(item, result, KeyConst.SOURCE)
    #         set_event_info_by_key(item, result, KeyConst.EVENT)  # Event
    #         set_event_info_by_key(item, result, KeyConst.HOST)
    #         if len(item_event_type) == 2:
    #             if EventTypeConst.CONNECTION in item_event_type and EventTypeConst.PROTOCOL in item_event_type:
    #                 set_event_info_by_key(item, result, KeyConst.DESTINATION)
    #                 set_event_info_by_key(item, result, KeyConst.SOURCE)
    #                 set_event_info_by_key(item, result, KeyConst.EVENT)  # Event
    #                 set_event_info_by_key(item, result, KeyConst.HOST)
    #             elif EventTypeConst.ACCESS in item_event_type and EventTypeConst.PROTOCOL in item_event_type:
    #                 set_event_info_by_key(item, result, KeyConst.DESTINATION)
    #                 set_event_info_by_key(item, result, KeyConst.SOURCE)
    #                 set_event_info_by_key(item, result, KeyConst.EVENT)  # Event
    #                 set_event_info_by_key(item, result, KeyConst.HOST)
    #         elif len(item_event_type) == 3:
    #             """
    #             """
    # elif len(item_event_category) == 2:
    #     """
    #     type == allowed
    #     위 조건 공통 으로 적용
    #     """
    #     set_event_info_by_key(item, result, KeyConst.DESTINATION)
    #     set_event_info_by_key(item, result, KeyConst.SOURCE)
    #     set_event_info_by_key(item, result, KeyConst.EVENT)  # Event
    #     set_event_info_by_key(item, result, KeyConst.HOST)
    #     if EventCategoryConst.NETWORK in item_event_category:
    #         if EventCategoryConst.WEB in item_event_category:
    #             if len(item_event_type) == 2:
    #                 if EventTypeConst.ACCESS in item_event_type and EventTypeConst.PROTOCOL in item_event_type:
    #                     """
    #                     두 조건의 결과가 같음
    #                     """
    #             elif len(item_event_type) == 3:
    #                 if EventTypeConst.CONNECTION in item_event_type and EventTypeConst.INFO in item_event_type and EventTypeConst.PROTOCOL in item_event_type:
    #                     """
    #                     두 조건의 결과가 같음
    #                     """
    #             set_event_info_by_key(item, result, KeyConst.DESTINATION)
    #             set_event_info_by_key(item, result, KeyConst.SOURCE)
    #             set_event_info_by_key(item, result, KeyConst.EVENT)  # Event
    #             set_event_info_by_key(item, result, KeyConst.HOST)
    #         elif EventCategoryConst.FILE in item_event_category:
    #             """
    #             (type == connection and type == protocol and type == info) or (type == connection and type == protocol and type == deletion and type == info)
    #             위 조건 공토 으로 적용
    #             """
    #             set_event_info_by_key(item, result, KeyConst.FILE, [])

    event = dict()

    if item_event_category is not None:
        event['category'] = item_event_category
    if item_event_type is not None:
        event['type'] = item_event_type

    result['event'] = event


def parse_auditbeat(item: dict, result: dict):
    item_event: dict = item.get('event')
    item_event_category = item_event.get('category')
    item_event_type = item_event.get('type')

    if item_event_category is not None and item_event_type is not None:
        set_event_info_by_key(item, result, KeyConst.EVENT)  # Event
        if EventCategoryConst.PROCESS in item_event_category and EventTypeConst.START in item_event_type:
            set_event_info_by_key(item, result, KeyConst.HOST)
            set_event_info_by_key(item, result, KeyConst.PROCESS)
            set_event_info_by_key(item, result, KeyConst.FILE)
        elif EventCategoryConst.FILE in item_event_category and EventTypeConst.CREATION in item_event_type:
            set_event_info_by_key(item, result, KeyConst.FILE)
            if EventTypeConst.CHANGE in item_event_type:
                set_event_info_by_key(item, result, KeyConst.PROCESS)
        elif (EventCategoryConst.SESSION in item_event_category and EventTypeConst.START in item_event_type) and\
             (EventCategoryConst.AUTHENTICATION in item_event_category and EventTypeConst.INFO in item_event_type):
            set_event_info_by_key(item, result, KeyConst.PROCESS)
            if EventCategoryConst.NETWORK in item_event_category and EventTypeConst.CONNECTION in item_event_type:
                set_event_info_by_key(item, result, KeyConst.DESTINATION)
                set_event_info_by_key(item, result, KeyConst.SOURCE)
                set_event_info_by_key(item, result, KeyConst.NETWORK)

    event = dict()

    if item_event_category is not None:
        event['category'] = item_event_category
    if item_event_type is not None:
        event['type'] = item_event_type

    result['event'] = event

def parse_killchain(item: dict, result: dict):

    item_host_ip: dict = item.get('host_ip')
    item_chain_ttps: dict = item.get('chain_ttps')
    item_subgraph: dict = item.get('subgraph')
    item_len_chain: dict = item.get('len_chain')
    item_chain_score: dict = item.get('chain_score')

    event = dict()

    if item_host_ip is not None:
        event['host_ip'] = item_host_ip
    if item_chain_ttps is not None:
        event['chain_ttps'] = item_chain_ttps
    if item_len_chain is not None:
        event['len_chain'] = item_len_chain
    if item_chain_score is not None:
        event['chain_score'] = item_chain_score
    if item_subgraph is not None:
        event['subgraph'] = item_subgraph

    result['killchain'] = event

def parse_event(item: dict) -> dict:
    """
    :param item:
    :return:
    """
    result = dict()

    _index = item.get('_index')

    result['_id'] = item.get('_id')
    result['_index'] = _index

    if _index == IndexConst.WINLOG_BEAT:
        parse_winlogbeat(item, result)
    elif _index == IndexConst.FILE_BEAT:
        parse_filebeat(item, result)
    elif _index == IndexConst.AUDIT_BEAT:
        parse_auditbeat(item, result)

    return result

def parse_chain(item: dict) -> dict:
    """
    :param item:
    :return:
    """
    result = dict()



    result['_id'] = item.get('_id')
    parse_killchain(item, result)

    return result

def add_mongo_query(params: dict, query_str: dict):
    if params is not None:
        for key in params.keys():
            value = params.get(key)
            if 'ttp' == key and value != '':
                query_str['mitre_attack_ttp'] = value
            elif 'host' == key and value != '':
                """
                destination.ip, source.ip, host.ip or 로 검색 해야함
                {$or: [{}, {}, {}]}
                """
                dest_ip = dict()
                dest_ip['destination.ip'] = value
                source_ip = dict()
                source_ip['source.ip'] = value
                host_ip = dict()
                host_ip['host.ip'] = value

                query_str['$or'] = [dest_ip, source_ip, host_ip]
            elif 'startTime' == key and value != '':
                """
                여기 시작 시간
                """
            elif 'endTime' == key and value != '':
                """
                여기 종료 시간
                """
            elif 'id' == key and value != '':
                query_str['_id'] = value


def sorted_tactic(list_data):
    navigator = TacticCollection.navigator
    for num in range(len(list_data)):
        if list_data[num]['name'].lower() in navigator:
            list_data[num]['sorted_num'] = navigator[list_data[num]['name'].lower()]
    sort_list = sorted(list_data, key=lambda item: item['sorted_num'])
    return sort_list