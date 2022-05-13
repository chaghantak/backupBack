from flask import jsonify

from .table import GroupCountryMap, CyberCampaignCollections, AttackSimpleInfoVer100, UiAccMenu, \
    CyberCampaignCollectionsPeFilename, CyberCampaignCollectionsPestudioResult
from database.mongo import get_db
from .util2 import *

attack_db_list = get_db('mitre_enterprise_attack')


class AttackCollection:
    MITRE_ATTACK_PATTERN = 'attack-pattern'
    MITRE_COURSE_OF_ACTION = 'course-of-action'
    MITRE_IDENTITY = 'identity'
    MITRE_INTRUSION_SET = 'intrusion-set'
    MITRE_MALWARE = 'malware'
    MITRE_MARKING_DEFINITION = 'marking-definition'
    MITRE_RELATIONSHIP = 'relationship'
    MITRE_TOOL = 'tool'
    MITRE_X_MITRE_DATA_COMPONENT = 'x-mitre-data-component'
    MITRE_X_MITRE_DATA_SOURCE = 'x-mitre-data-source'
    MITRE_X_MITRE_TACTIC = 'x-mitre-tactic'
    MITRE_X_MITRE_MATRIX = 'x-mitre-matrix'


class CampaignService:
    @staticmethod
    def get_group_list():
        result = []

        for group in GroupCountryMap.query.all():
            group = group.__dict__
            del (group['_sa_instance_state'])
            group['index'] = int(group['index'])
            result.append(group)

        if not result:
            return jsonify({'result': 'error', 'message': '값이 없습니다.'})

        return {'result': 'success', 'items': result}

    @staticmethod
    def get_campaign_list():
        result = []

        join_data = CyberCampaignCollections.query \
            .join(CyberCampaignCollectionsPeFilename, CyberCampaignCollectionsPeFilename.filename ==
                  CyberCampaignCollections.filename) \
            .join(CyberCampaignCollectionsPestudioResult, CyberCampaignCollectionsPestudioResult.pe_name ==
                  CyberCampaignCollectionsPeFilename.pe_name) \
            .add_columns(CyberCampaignCollectionsPestudioResult.pestudio_processed) \
            .all()
        for campaign_all in join_data:
            campaign = campaign_all[0]
            campaign = campaign.__dict__
            del (campaign['_sa_instance_state'])
            del (campaign['append_datetime'])
            campaign['pestudio_processed'] = campaign_all[1]
            result.append(campaign)

        """for campaign in CyberCampaignCollections.query.all():
            campaign = campaign.__dict__
            del(campaign['_sa_instance_state'])
            del(campaign['append_datetime'])
            campaign['index'] = int(campaign['index'])
            result.append(campaign)

        if not result:
            return jsonify({'result': 'error', 'message': '값이 없습니다.'})"""

        return {'result': 'success', 'items': result}

    @staticmethod
    def get_campaign_ttps(params):
        result = []
        tactic_navi = TacticCollection.navi
        search_navi = TacticCollection.navigator
        for k, v in tactic_navi.items():
            tac = {}
            tac['id'] = v
            tac['name'] = k
            tac['techniques'] = []
            result.append(tac)
        if not params:
            return {'items': result, 'result': 'faild'}
        split_params = params['ttp'].split(' ')
        if len(split_params) < 1:
            return {'items': result, 'result': 'faild'}
        for ttp in split_params:
            ttp_info = AttackSimpleInfoVer100.query.filter_by(ttp=ttp).first()
            if ttp_info is None:
                return {'items': result, 'result': 'faild'}
            ttp_info = ttp_info.__dict__
            table = DictMaker(ttp_info)
            tactic, tech, subtech = table.tacticmaker(ttp_info), table.techmaker(ttp_info), table.subtechmaker(ttp_info)
            if not result[search_navi[tactic['name']] - 1]['techniques']:
                if subtech:
                    tech['subTechniques'].append(subtech)
                result[search_navi[tactic['name']] - 1]['techniques'].append(tech)
            else:
                is_tach = True
                for idx in range(len(result[search_navi[tactic['name']] - 1]['techniques'])):
                    if result[search_navi[tactic['name']] - 1]['techniques'][idx]['id'] == tech['id']:
                        is_tach = False
                        if subtech:
                            result[search_navi[tactic['name']] - 1]['techniques'][idx]['subTechniques'].append(subtech)
                if is_tach:
                    if subtech:
                        tech['subTechniques'].append(subtech)
                    result[search_navi[tactic['name']] - 1]['techniques'].append(tech)
        return {'items': result, 'result': 'success'}

    @staticmethod
    def get_gui_menu(params):
        result = []

        dbs = UiAccMenu.query.filter_by(gui_type=params['gui']).all()

        if dbs is None:
            return jsonify({'result': 'error', 'message': '값이 없습니다.'})

        for db in dbs:
            dict_db = db.__dict__
            del (dict_db['_sa_instance_state'])
            dict_db['parent_id'] = int(dict_db['parent_id'])
            dict_db['index'] = int(dict_db['index'])
            dict_db['depth'] = int(dict_db['depth'])
            result.append(dict_db)

        return {"items": result, "result": "success"}

    @staticmethod
    def get_join_campaign(params):
        result = []

        join_data = CyberCampaignCollections.query \
            .join(GroupCountryMap, GroupCountryMap.name == CyberCampaignCollections.attack_group) \
            .add_columns(CyberCampaignCollections.attack_group, CyberCampaignCollections.attack_year,
                         GroupCountryMap.country, CyberCampaignCollections.true_ttps, CyberCampaignCollections.index) \
            .all()

        for data in join_data:
            table = DictMaker(data)
            data = table.columnsmaker(data)
            result.append(data)

        result = sorted_option(result, params)

        return {'items': result}

    @staticmethod
    def get_filename(params):
        result = []

        if 'time' not in params or 'country' not in params:
            return {'items': result, 'message': 'faild'}

        join_data = CyberCampaignCollections.query \
            .join(GroupCountryMap, GroupCountryMap.name == CyberCampaignCollections.attack_group) \
            .filter(GroupCountryMap.country == params['country'],
                    CyberCampaignCollections.attack_year == params['time']) \
            .all()
        for data in join_data:
            data = data.__dict__
            filter_db = CyberCampaignCollectionsPeFilename.query.filter_by(filename=data['filename']).all()
            for db in filter_db:
                temp = {}
                db = db.__dict__
                temp['url'] = db['pe_name'].split('.')[0] + '.png'
                result.append(temp)
        if result:
            return {'items': result, 'result': 'success'}
        else:
            return {'items': result, 'message': 'faild'}

    @staticmethod
    def get_maplist():
        result = []
        country = []

        join_data = CyberCampaignCollections.query \
            .join(GroupCountryMap, GroupCountryMap.name == CyberCampaignCollections.attack_group) \
            .add_columns(GroupCountryMap.country) \
            .all()

        for data in join_data:
            country.append(data[1])

        set_country = list(set(country))
        temp_dict = {}

        for data in range(len(set_country)):
            temp_dict[set_country[data]] = country.count(set_country[data])

        sort_data = sorted(temp_dict.items(), key=lambda item: item[1])

        for k, v in sort_data:
            dict = {'country': k, 'value': v}
            result.append(dict)
        return {'items': result}

    @staticmethod
    def get_rankcount():
        result = []
        result_dict = {}
        week = week_count()

        # 캠페인 랭크
        campaign_length = CyberCampaignCollections.query \
            .join(GroupCountryMap, GroupCountryMap.name == CyberCampaignCollections.attack_group) \
            .count()

        campaign_week = CyberCampaignCollections.query \
            .join(GroupCountryMap, GroupCountryMap.name == CyberCampaignCollections.attack_group) \
            .filter(CyberCampaignCollections.append_datetime > week) \
            .count()

        result_dict['campaign_length'] = campaign_length
        result_dict['campaign_week'] = campaign_week

        # pe 랭크
        pe_length = CyberCampaignCollectionsPestudioResult.query.count()

        pe_week = CyberCampaignCollectionsPestudioResult.query.filter(
            CyberCampaignCollectionsPestudioResult.append_datetime > week).count()

        result_dict['pe_length'] = pe_length
        result_dict['pe_week'] = pe_week

        result.append(result_dict)

        return {'items': result, 'result': 'success'}

    @staticmethod
    def get_domain(params):
        return params

    @staticmethod
    def get_tactic_info():
        result = []

        db_all = AttackSimpleInfoVer100.query.all()

        for db in db_all:
            db = db.__dict__
            db['index'] = int(db['index'])
            del(db['_sa_instance_state'])
            result.append(db)

        return {'item': result}

