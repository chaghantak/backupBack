from flask_restx import Resource
from flask import request

from .dto import CampaignDto
from .service import CampaignService

api = CampaignDto.api


@api.route('/group-list')
class GroupList(Resource):
    def post(self):
        """
        postgres: group_country_map
        """
        return CampaignService.get_group_list()


@api.route('/campaign-list')
class CampaignList(Resource):
    def post(self):
        """
        postgres: cyber_campaign_collections
        """
        return CampaignService.get_campaign_list()


@api.route('/campaign-ttps')
class CampaignTtps(Resource):
    @api.expect(CampaignDto.ttp_search)
    def post(self):
        """
        postgres: attack_simple_info_ver100
        """
        params = request.get_json()
        return CampaignService.get_campaign_ttps(params)


@api.route('/campaign-gui')
class Uimenu(Resource):
    @api.expect(CampaignDto.gui_search)
    def post(self):
        """
        postgres: ui_acc_menu
        """
        params = request.get_json()
        return CampaignService.get_gui_menu(params)


@api.route('/campaign-list-join')
class CampaignJoin(Resource):
    @api.expect(CampaignDto.attack_table_params)
    def post(self):
        """
        postgres: group_country_map, cyber_campaign_collections
        """
        params = request.get_json()
        return CampaignService.get_join_campaign(params)


@api.route('/campaign-filename')
class CampaignFileName(Resource):
    @api.expect(CampaignDto.file_search)
    def post(self):
        """
        postgres: cyber_campaign_collections, group_country_map, cyber_campaign_collections_pe_filename
        """
        params = request.get_json()
        return CampaignService.get_filename(params)


@api.route('/map-list')
class MapList(Resource):
    def post(self):
        """
        postgres: cyber_campaign_collections, group_country_map
        """
        return CampaignService.get_maplist()


@api.route('/rank-count')
class RankCount(Resource):
    def post(self):
        """
        postgres: cyber_campaign_collections, group_country_map, cyber_campaign_collections_pe_studio_result
        """
        return CampaignService.get_rankcount()


@api.route('/test')
class DomainConvert(Resource):
    @api.expect(CampaignDto.test_params)
    def post(self):
        """

        """
        params = request.get_json()
        return CampaignService.get_domain(params)


@api.route('/tactic-info')
class TacticInfo(Resource):
    def post(self):
        """
        postgres: attack_simple_info_ver100
        """
        return CampaignService.get_tactic_info()