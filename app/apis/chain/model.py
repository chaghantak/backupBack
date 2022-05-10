from typing import List, Dict


class BaseModel:
    def __init__(self, key: str, name: str):
        self._id: str = key
        self._name: str = name

    @property
    def id(self) -> str:
        return self._id

    @id.setter
    def id(self, key):
        self._id = key

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, name):
        self._name = name


class Event:
    def __init__(self, key: str, index: str, timestamp: str):
        self._id = key
        self._index = index
        self._timestamp = timestamp

    def get_dict(self) -> dict:
        return dict(id=self.id, index=self.index, timestamp=self.timestamp)

    @property
    def id(self) -> str:
        return self._id

    @id.setter
    def id(self, key):
        self._id = key

    @property
    def index(self) -> str:
        return self._index

    @index.setter
    def index(self, index):
        self._index = index

    @property
    def timestamp(self) -> str:
        return self._timestamp

    @timestamp.setter
    def timestamp(self, timestamp):
        self._timestamp = timestamp


class SubTechnique(BaseModel):
    def __init__(self, key: str, name: str):
        super(SubTechnique, self).__init__(key, name)
        self._events: List[str] = []

    def get_dict(self) -> dict:

        return dict(id=self.id, name=self.name, events=len(self.events))

    @property
    def events(self) -> List[str]:
        return self._events

    @events.setter
    def events(self, value):
        if value not in self.events:
            self._events.append(value)


class Technique(BaseModel):
    def __init__(self, key: str, name: str):
        super(Technique, self).__init__(key, name)
        self._subTechniques: Dict[str, SubTechnique] = dict()
        self._events: List[str] = []

    def get_dict(self) -> dict:
        subTechniques: List[dict] = []
        for item in self.subTechniques.values():
            subTechniques.append(item.get_dict())

        return dict(id=self.id, name=self.name, subTechniques=subTechniques, events=len(self.events))

    @property
    def subTechniques(self) -> Dict[str, SubTechnique]:
        return self._subTechniques

    @subTechniques.setter
    def subTechniques(self, args):
        key, subTechnique = args
        if self._subTechniques.__contains__(key) is False:
            self._subTechniques[key] = subTechnique

    @property
    def events(self) -> List[str]:
        return self._events

    @events.setter
    def events(self, value):
        if value not in self.events:
            self._events.append(value)


class Tactic(BaseModel):
    def __init__(self, key: str, name: str):
        super(Tactic, self).__init__(key, name)
        self._techniques: Dict[str, Technique] = dict()

    def get_dict(self) -> dict:
        techniques: List[dict] = []
        for item in self._techniques.values():
            techniques.append(item.get_dict())

        return dict(id=self.id, name=self.name, techniques=techniques)

    @property
    def techniques(self) -> Dict[str, Technique]:
        return self._techniques

    @techniques.setter
    def techniques(self, args):
        key, technique = args
        if self._techniques.__contains__(key) is False:
            self._techniques[key] = technique


class TtpEvent(Event):
    def __init__(self, key: str, index: str, timestamp: str, ip: str, name: str):
        super(TtpEvent, self).__init__(key, index, timestamp)
        self._ip = ip
        self._name = name

    def get_dict(self) -> dict:
        return dict(id=self.id, index=self.index, timestamp=self.timestamp, ip=self.ip, name=self.name)

    @property
    def ip(self) -> str:
        return self._ip

    @ip.setter
    def ip(self, ip):
        self._ip = ip

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, name):
        self._name = name


class DetailEvent(Event):
    def __init__(self, key: str, index: str, timestamp: str):
        super(DetailEvent, self).__init__(key, index, timestamp)
