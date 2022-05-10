from database.postgres import get_db


db = get_db('classification_dummy')


class AttackSimpleInfoVer100(db.Model):
    __tablename__ = 'attack_simple_info_ver100'

    index = db.Column(db.Integer(), primary_key=True)
    ttp = db.Column(db.Text())
    tactic_name = db.Column(db.Text())
    technique_name = db.Column(db.Text())
    subtechnique_name = db.Column(db.Text())


class Countries(db.Model):
    __tablename__ = 'countries'

    index = db.Column(db.Integer(), primary_key=True)
    country = db.Column(db.Text())


class CyberCampaignCollections(db.Model):
    __tablename__ = 'cyber_campaign_collections'

    index = db.Column(db.Integer(), primary_key=True)
    filename = db.Column(db.Text())
    attack_year = db.Column(db.Text())
    attack_group = db.Column(db.Text())
    append_datetime = db.Column(db.Time())
    true_ttps = db.Column(db.Text())
    rcatt_ttps = db.Column(db.Text())
    rcatt_ttps_processed = db.Column(db.Boolean())
    tram_ttps = db.Column(db.Text())
    tram_ttps_processed = db.Column(db.Boolean())


class CyberCampaignCollectionsPeFilename(db.Model):
    __tablename__ = 'cyber_campaign_collections_pe_filename'

    index = db.Column(db.Integer(), primary_key=True)
    pe_name = db.Column(db.Text())
    filename = db.Column(db.Text())
    pe_filepath = db.Column(db.Text())


class CyberCampaignCollectionsPestudioResult(db.Model):
    __tablename__ = 'cyber_campaign_collections_pestudio_result'

    index = db.Column(db.Numeric(), primary_key=True)
    pe_name = db.Column(db.Text())
    pestudio_ttps = db.Column(db.Text())
    pestudio_processed = db.Column(db.Boolean())
    append_datetime = db.Column(db.Time())


class GroupCountryMap(db.Model):
    __tablename__ = 'group_country_map'

    index = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.Text())
    ttps = db.Column(db.Text())
    country = db.Column(db.Text())


class UiAccMenu(db.Model):
    __tablename__ = 'ui_acc_menu'

    index = db.Column(db.Integer(), primary_key=True)
    gui_type = db.Column(db.Text())
    train_type = db.Column(db.Text())
    depth = db.Column(db.Numeric())
    parent_id = db.Column(db.Numeric())
    type = db.Column(db.Text())
    value = db.Column(db.Text())
