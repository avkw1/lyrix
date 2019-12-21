# -*- coding: utf-8 -*-
"""
Lyrix integration module

@author: Alexander Korolev (avkw@bk.ru)
"""

from suds.client import Client
from suds.transport import TransportError
from suds import WebFault
from urllib2 import URLError
from datetime import datetime, timedelta
from threading import RLock
import cPickle as pickle
import tempfile
import time
import os

#import logging
#logging.basicConfig(level=logging.INFO)
#logging.getLogger('suds.client').setLevel(logging.DEBUG)


class AccessDeniedException(Exception):
    "Base class for access denied exceptions"
    def __init__(self, cause):
        super(AccessDeniedException, self).__init__()
        self.cause = cause

    def __str__(self):
        return self.cause


class WrongFacilityException(AccessDeniedException):
    "Access denied because of wrong facility code"
    def __init__(self, facility):
        super(WrongFacilityException, self).__init__("Wrong facility")
        self.facility = facility

    def __str__(self):
        return super(WrongFacilityException, self).__str__() + \
               " (" + str(self.facility) + ")"


class UnknownCardException(AccessDeniedException):
    "Access denied because the card is unknown"
    def __init__(self, number):
        super(UnknownCardException, self).__init__("Unknown card")
        self.number = number

    def __str__(self):
        return super(UnknownCardException, self).__str__() + \
               " (" + str(self.number) + ")"


class CardInactiveException(AccessDeniedException):
    "Access denied because the card is not active"
    def __init__(self, number, userid=None, issueid=None, starttime=None,
                 endtime=None):
        super(CardInactiveException, self).__init__("Card inactive")
        self.number = number
        self.userid = userid
        self.issueid = issueid
        self.starttime = starttime
        self.endtime = endtime

    def __str__(self):
        return super(CardInactiveException, self).__str__() + \
               " (" + str(self.number) + ")"


class AccessLevelViolationException(AccessDeniedException):
    "Access denied because of wrong access level"
    def __init__(self, number, userid=None, issueid=None):
        super(AccessLevelViolationException, self).__init__(\
        "Access level violation")
        self.number = number
        self.userid = userid
        self.issueid = issueid

    def __str__(self):
        return super(AccessLevelViolationException, self).__str__() + \
               " (" + str(self.number) + ")"


class LyrixMessage(object):
    "Message for Lyrix system. The class is used for offline operation"

    def __init__(self, sourceObject, code, causeObject=None):
        self.additionalFields = None
        self.alarmLevel = 0
        self.causeObject = causeObject
        self.code = code
        self.messID = None
        self.online = True
        self.priority = 0
        self.regTime = None
        self.service = False
        self.sourceObject = sourceObject
        self.time = datetime.utcnow()

    def append(self, **fields):
        "Append additional fields to the message"
        if self.additionalFields == None:
            self.additionalFields = {"item":[]}
        for key, value in fields.items():
            self.additionalFields["item"].append({"name":key, "value":value})


class LyrixMessageFactory(object):
    "Factory class for creating Lyrix messages"

    PR_LOW = 1000
    PR_MIDDLE = 10000
    PR_HIGH = 20000

    AL_NORMAL = 1000
    AL_WARNING = 10000
    AL_ALARM = 20000

    def __init__(self, source_object_id=None):
        self.source_object_id = source_object_id

    def create(self, code, cause_object_id=None):
        "Create new message"
        return LyrixMessage(self.source_object_id, code, cause_object_id)

    def create_AccessDeniedWrongFacility(self, cardfacility):
        "Create \"AccessDeniedWrongFacility\" message"
        message = self.create("AccessDeniedWrongFacility")
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CardFacility=cardfacility)
        return message

    def create_AccessDeniedUnknownCard(self, cardnumber):
        "Create \"AccessDeniedUncnownCard\" message"
        message = self.create("AccessDeniedUncnownCard")
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CardNumber=cardnumber)
        return message

    def create_AccessDeniedCardInactive(self, cardnumber, issueid, userid):
        "Create \"AccessDeniedCardInactive\" message"
        message = self.create("AccessDeniedCardInactive", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CardNumber=cardnumber, Issue=issueid)
        return message

    def create_AccessDeniedAccessLevelViolation(self, cardnumber, issueid,
                                                userid):
        "Create \"AccessDeniedAccessLevelViolation\" message"
        message = self.create("AccessDeniedAccessLevelViolation", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CardNumber=cardnumber, Issue=issueid)
        return message

    def create_AccessDeniedExtFieldCheck(self, cardnumber, issueid, userid,
                                         field_name, field_value, ext_info):
        "Create \"AccessDeniedExtFieldCheck\" message"
        message = self.create("AccessDeniedExtFieldCheck", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CardNumber=cardnumber, Issue=issueid,
                       FieldName=field_name, FieldValue=field_value,
                       ExtendedInfo=ext_info)
        return message

    def create_AccessGrantedPutThings(self, cardnumber, issueid, userid,
                                      cellnumber):
        "Create \"AccessGrantedPutThings\" message"
        message = self.create("AccessGrantedPutThings", userid)
        message.alarmLevel = LyrixMessageFactory.AL_NORMAL
        message.priority = LyrixMessageFactory.PR_LOW
        message.append(CardNumber=cardnumber, Issue=issueid,
                       CellNumber=cellnumber)
        return message

    def create_AccessGrantedNoPutThings(self, cardnumber, issueid, userid):
        "Create \"AccessGrantedNoPutThings\" message"
        message = self.create("AccessGrantedNoPutThings", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CardNumber=cardnumber, Issue=issueid)
        return message

    def create_AccessGrantedTakeAwayThings(self, cardnumber, issueid, userid,
                                           cellnumber):
        "Create \"AccessGrantedTakeAwayThings\" message"
        message = self.create("AccessGrantedTakeAwayThings", userid)
        message.alarmLevel = LyrixMessageFactory.AL_NORMAL
        message.priority = LyrixMessageFactory.PR_LOW
        message.append(CardNumber=cardnumber, Issue=issueid,
                       CellNumber=cellnumber)
        return message

    def create_AccessGrantedNoTakeAwayThings(self, cardnumber, issueid, userid,
                                             cellnumber):
        "Create \"AccessGrantedNoTakeAwayThings\" message"
        message = self.create("AccessGrantedNoTakeAwayThings", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CardNumber=cardnumber, Issue=issueid,
                       CellNumber=cellnumber)
        return message

    def create_DoorForcedOpenAlarm(self, cellnumber, cardnumber=None,
                                  issueid=None, userid=None):
        "Create \"DoorForcedOpenAlarm\" message"
        message = self.create("DoorForcedOpenAlarm", userid)
        message.alarmLevel = LyrixMessageFactory.AL_ALARM
        message.priority = LyrixMessageFactory.PR_HIGH
        if cardnumber:
            message.append(CardNumber=cardnumber, Issue=issueid)
        message.append(CellNumber=cellnumber)
        return message

    def create_ForgottenThings(self, cardnumber, issueid, userid, cellnumber):
        "Create \"ForgottenThings\" message"
        message = self.create("ForgottenThings", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CardNumber=cardnumber, Issue=issueid,
                       CellNumber=cellnumber)
        return message

    def create_CellFailure(self, cellnumber):
        "Create \"CellFailure\" message"
        message = self.create("CellFailure")
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CellNumber=cellnumber)
        return message

    def create_CellEnabledByAdmin(self, cellnumber, cardnumber=None,
                                  issueid=None, userid=None):
        "Create \"CellEnabledByAdmin\" message"
        message = self.create("CellEnabledByAdmin", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        if cardnumber:
            message.append(CardNumber=cardnumber, Issue=issueid)
        message.append(CellNumber=cellnumber)
        return message

    def create_CellDisabledByAdmin(self, cellnumber, cardnumber=None,
                                   issueid=None, userid=None):
        "Create \"CellDisabledByAdmin\" message"
        message = self.create("CellDisabledByAdmin", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        if cardnumber:
            message.append(CardNumber=cardnumber, Issue=issueid)
        message.append(CellNumber=cellnumber)
        return message

    def create_CellAutoDisabled(self, cellnumber, cardnumber=None,
                                issueid=None, userid=None):
        "Create \"CellAutoDisabled\" message"
        message = self.create("CellAutoDisabled", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        if cardnumber:
            message.append(CardNumber=cardnumber, Issue=issueid)
        message.append(CellNumber=cellnumber)
        return message

    def create_ThingsInEmptyCell(self, cellnumber):
        "Create \"ThingsInEmptyCell\" message"
        message = self.create("ThingsInEmptyCell")
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CellNumber=cellnumber)
        return message

    def create_NoThingsInBusyCell(self, cardnumber, issueid, userid,
                                  cellnumber):
        "Create \"NoThingsInBusyCell\" message"
        message = self.create("NoThingsInBusyCell", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CardNumber=cardnumber, Issue=issueid,
                       CellNumber=cellnumber)
        return message

    def create_CellOpenByAdmin(self, cellnumber, cardnumber=None, issueid=None,
                               userid=None, ext_info=None):
        "Create \"CellOpenByAdmin\" message"
        message = self.create("CellOpenByAdmin", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        if cardnumber:
            message.append(CardNumber=cardnumber, Issue=issueid)
        message.append(CellNumber=cellnumber)
        if ext_info:
            message.append(ExtendedInfo=ext_info)
        return message

    def create_USBRS485Disconnect(self):
        "Create \"USBRS485Disconnect\" message"
        message = self.create("USBRS485Disconnect")
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        return message

    def create_ModuleDisconnect(self, address):
        "Create \"ModuleDisconnect\" message"
        message = self.create("ModuleDisconnect")
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(ModuleAddress=address)
        return message

    def create_URSDisconnect(self, address):
        "Create \"URSDisconnect\" message"
        message = self.create("URSDisconnect")
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(URSAddress=address)
        return message

    def create_ReaderCommandPIN10(self, cardnumber, issueid, userid):
        "Create \"ReaderCommandPIN10\" message"
        message = self.create("ReaderCommandPIN10", userid)
        message.alarmLevel = LyrixMessageFactory.AL_NORMAL
        message.priority = LyrixMessageFactory.PR_LOW
        message.append(CardNumber=cardnumber, Issue=issueid)
        return message

    def create_RelayActivated(self):
        "Create \"RelayActivated\" message"
        message = self.create("RelayActivated")
        message.alarmLevel = LyrixMessageFactory.AL_NORMAL
        message.priority = LyrixMessageFactory.PR_LOW
        message.append(eRelayState="rlsOn")
        return message

    def create_RelayDeactivated(self):
        "Create \"RelayDeactivated\" message"
        message = self.create("RelayDeactivated")
        message.alarmLevel = LyrixMessageFactory.AL_NORMAL
        message.priority = LyrixMessageFactory.PR_LOW
        message.append(eRelayState="rlsOff")
        return message

    def create_WillAccess(self, cardnumber, issueid, userid):
        "Create \"WillAccess\" message"
        message = self.create("WillAccess", userid)
        message.alarmLevel = LyrixMessageFactory.AL_NORMAL
        message.priority = LyrixMessageFactory.PR_LOW
        message.append(CardNumber=cardnumber, Issue=issueid)
        return message

    def create_AccessGranted(self, cardnumber, issueid, userid):
        "Create \"AccessGranted\" message"
        message = self.create("AccessGranted", userid)
        message.alarmLevel = LyrixMessageFactory.AL_NORMAL
        message.priority = LyrixMessageFactory.PR_LOW
        message.append(CardNumber=cardnumber, Issue=issueid)
        return message

    def create_AdminAccessGranted(self, cardnumber, issueid, userid):
        "Create \"AdminAccessGranted\" message"
        message = self.create("AdminAccessGranted", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CardNumber=cardnumber, Issue=issueid)
        return message

    def create_DuressAccess(self, cardnumber, issueid, userid):
        "Create \"DuressAccess\" message"
        message = self.create("DuressAccess", userid)
        message.alarmLevel = LyrixMessageFactory.AL_ALARM
        message.priority = LyrixMessageFactory.PR_HIGH
        message.append(CardNumber=cardnumber, Issue=issueid)
        return message

    def create_alcohol(self, cardnumber, userid, value, fail, r_name,
                       units=None, ext_info=None):
        "Create \"alcohol?.??\" message"
        if units:
            message = self.create("alcohol%d.%02d%s" % (value // 100,
                                                        value % 100,
                                                        units), userid)
        else:
            message = self.create("alcohol%d.%02d" % (value // 100,
                                                      value % 100), userid)
        if fail:
            message.alarmLevel = LyrixMessageFactory.AL_ALARM
            message.priority = LyrixMessageFactory.PR_HIGH
        else:
            message.alarmLevel = LyrixMessageFactory.AL_NORMAL
            message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CardNumber=cardnumber, PenaltyReason=r_name)
        if ext_info:
            message.append(ExtendedInfo=ext_info)
        return message

    def create_AlcotesterBreathErr(self, cardnumber, userid, r_name):
        "Create \"AlcotesterBreathErr\" message"
        message = self.create("AlcotesterBreathErr", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CardNumber=cardnumber, PenaltyReason=r_name)
        return message

    def create_AlcotesterTimeout(self, cardnumber, userid, r_name):
        "Create \"AlcotesterTimeout\" message"
        message = self.create("AlcotesterTimeout", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        message.append(CardNumber=cardnumber, PenaltyReason=r_name)
        return message

    def create_AlcotesterFailure(self, ext_info=None):
        "Create \"AlcotesterFailure\" message"
        message = self.create("AlcotesterFailure")
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        if ext_info:
            message.append(ExtendedInfo=ext_info)
        return message

    def create_AlcotesterDisconnect(self):
        "Create \"AlcotesterDisconnect\" message"
        message = self.create("AlcotesterDisconnect")
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        return message

    def create_TemperatureChanged(self, alarmLevel, priority, value):
        "Create \"TemperatureChanged\" message"
        message = self.create("TemperatureChanged")
        message.alarmLevel = alarmLevel
        message.priority = priority
        message.append(TemperatureValue=value)
        return message

    def create_TemperatureSensorFailure(self):
        "Create \"TemperatureSensorFailure\" message"
        message = self.create("TemperatureSensorFailure")
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        return message

    def create_SPGTError(self, text,
                         cardnumber=None, issueid=None, userid=None,
                         z_number=None, l_number=None, i_number=None):
        "Create \"SPGTError\" message"
        message = self.create("SPGTError", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        if cardnumber != None:
            message.append(CardNumber=cardnumber)
        if issueid != None:
            message.append(Issue=issueid)
        if z_number != None:
            message.append(SPGTZNumber=z_number)
        if l_number != None:
            message.append(SPGTLNumber=l_number)
        if i_number != None:
            message.append(SPGTINumber=i_number)
        message.append(ExtendedInfo=text)
        return message

    def create_SPGTLampOut(self, cardnumber, issueid, userid,
                           z_number, l_number, i_number):
        "Create \"SPGTLampOut\" message"
        message = self.create("SPGTLampOut", userid)
        message.alarmLevel = LyrixMessageFactory.AL_NORMAL
        message.priority = LyrixMessageFactory.PR_LOW
        message.append(CardNumber=cardnumber, Issue=issueid,
                       SPGTZNumber=z_number, SPGTLNumber=l_number,
                       SPGTINumber=i_number)
        return message

    def create_SPGTLampOutReplace(self, cardnumber, issueid, userid,
                                  z_number, l_number, i_number):
        "Create \"SPGTLampOutReplace\" message"
        message = self.create("SPGTLampOutReplace", userid)
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_LOW
        message.append(CardNumber=cardnumber, Issue=issueid,
                       SPGTZNumber=z_number, SPGTLNumber=l_number,
                       SPGTINumber=i_number)
        return message

    def create_SPGTLampIn(self, cardnumber, issueid, userid,
                          z_number, l_number, i_number):
        "Create \"SPGTLampIn\" message"
        message = self.create("SPGTLampIn", userid)
        message.alarmLevel = LyrixMessageFactory.AL_NORMAL
        message.priority = LyrixMessageFactory.PR_LOW
        if cardnumber != None:
            message.append(CardNumber=cardnumber, Issue=issueid)
        message.append(SPGTZNumber=z_number, SPGTLNumber=l_number,
                       SPGTINumber=i_number)
        return message

    def create_ACPowerLoss(self):
        "Create \"ACPowerLoss\" message"
        message = self.create("ACPowerLoss")
        message.alarmLevel = LyrixMessageFactory.AL_WARNING
        message.priority = LyrixMessageFactory.PR_MIDDLE
        return message

    def create_ACPowerRecovery(self):
        "Create \"ACPowerRecovery\" message"
        message = self.create("ACPowerRecovery")
        message.alarmLevel = LyrixMessageFactory.AL_NORMAL
        message.priority = LyrixMessageFactory.PR_LOW
        return message


class LyrixConfig(object):
    "Configuration for class Lyrix"

    def __init__(self, wsdl_url, user, password, facility_codes=None,
                 access_levels=None):
        self.wsdl_url = wsdl_url
        self.user = user
        self.password = password
        self.timeout = 10
        self.reconnect_interval_s = 300
        self.cache_livetime_m = 720
        if facility_codes != None:
            self.facility_codes = facility_codes
        else:
            self.facility_codes = []
        if access_levels != None:
            self.access_levels = access_levels
        else:
            self.access_levels = []
        self.card_cache_file = None
        self.messages_file = None


class LyrixCardCache(object):
    "Card cache class for Lyrix integration"

    def __init__(self, livetime_m=0, file_name=None):
        assert isinstance(livetime_m, int)
        if file_name:
            assert isinstance(file_name, str)
        self.livetime_m = livetime_m
        self.file_name = file_name
        self._lock = RLock()
        self._cache = []
        self._cache_time = None

    def load(self):
        "Load card cache from file"
        if self.file_name == None:
            return
        try:
            cache_file = open(self.file_name, "rb")
            card_cache = pickle.load(cache_file)
            cache_file.close()
            with self._lock:
                self._cache = card_cache
                # Set "None" time to update cache as soon as possible
                self._cache_time = None
                #print "LOAD CARD CACHE: ", self._cache
        except Exception:
            # Ignore all exceptions
            pass

    def save(self):
        "Save card cache to file"
        if self.file_name == None:
            return
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(".p", "lyrix-cc-")
            tmp_file = os.fdopen(tmp_fd, "w")
            #print "TMP_FILE: ", tmp_path
            with self._lock:
                pickle.dump(self._cache, tmp_file, pickle.HIGHEST_PROTOCOL)
            tmp_file.close()
            os.rename(tmp_path, self.file_name)
            #print "%s -> %s" % (tmp_path, self.file_name)
        except Exception:
            # Ignore all exceptions
            pass

    def is_empty(self):
        "Check whether cache is empty"
        with self._lock:
            if len(self._cache):
                return False
        return True

    def is_expired(self):
        "Returns True if cache is expired"
        with self._lock:
            if self._cache_time == None:
                return True
            if self.livetime_m > 0:
                delta = datetime.utcnow() - self._cache_time
                if delta >= timedelta(minutes=self.livetime_m):
                    return True
        return False

    def update(self, new_cache, auto_save=True):
        "Update cache"
        assert isinstance(new_cache, list)
        assert isinstance(auto_save, bool)
        with self._lock:
            old_cache = self._cache
            self._cache = new_cache
            self._cache_time = datetime.utcnow()
            #print "FILL CARD CACHE: ", self._cache
            if auto_save and 0 != cmp(old_cache, new_cache):
                self.save()

    def check_card(self, number):
        "Check whether card number is in a cache"
        with self._lock:
            if number in self._cache:
                return True
        return False


class Lyrix(object):
    "Main class for Lyrix integration"

    def __init__(self, config):
        assert isinstance(config, LyrixConfig)
        self.config = config
        self._lock = RLock()
        self._card_cache = LyrixCardCache(self.config.cache_livetime_m,
                                          self.config.card_cache_file)
        self._message_queue = []
        # Try to load messages from file
        self._load_messages()
        self._lclient = LyrixClient(self.config.wsdl_url, self.config.user,
                                    self.config.password,
                                    self.config.reconnect_interval_s,
                                    self.config.timeout)
        # Try to connect to Lyrix
        self._lclient.check_connection()

    @property
    def connected(self):
        "True if client connected to service"
        return self._lclient.connected

    def shutdown(self):
        "Disconnect from Lyrix"
        del self._lclient

    def check_card_access(self, cardcode):
        "Returns UserCardData, IssueID if card has access"
        with self._lock:
            # Check facility (both online and offline modes)
            if cardcode.facility not in self.config.facility_codes:
                raise WrongFacilityException(cardcode.facility)

            while True:
                # Check connection and try to reconnect if needed
                if not self._lclient.check_connection():
                    return self._check_card_access_offline(cardcode)
                # Try to work online
                try:
                    return self._check_card_access_online(cardcode)
                except DisconnectException:
                    continue
                except WebServiceError:
                    try:
                        self._lclient.logoff()
                    except Exception:
                        pass
                    finally:
                        self._lclient.disconnect()
                    continue

    def send_message(self, message):
        "Send message (online mode) or append it to queue (offline mode)"
        assert isinstance(message, LyrixMessage)
        with self._lock:
            self._message_queue.append(message.__dict__)
            self.send_queued_messages()

    def send_queued_messages(self):
        "Try to send messages form queue"
        with self._lock:
            while len(self._message_queue) > 0:
                if not self._lclient.check_connection():
                    break
                try:
                    self._prepare_messages()
                    self._lclient.sendMessages(self._message_queue)
                    #num = 1
                    #for msg in self._message_queue:
                        #print num, msg
                        #num += 1
                    self._message_queue = []
                    break
                except DisconnectException:
                    continue
                except WebServiceError:
                    try:
                        self._lclient.logoff()
                    except Exception:
                        pass
                    finally:
                        self._lclient.disconnect()
                    continue
            # Save enqueued messages or remove file if queue is empty
            self._save_messages()

    def _check_card_access_online(self, cardcode):
        "Check card function (connection established)"
        ucdl = self._lclient.getUserCardDataByCardIssue(cardcode.number)
        if len(ucdl) < 1:
            raise UnknownCardException(cardcode.number)
        usercarddata = ucdl[0]
        #print usercarddata
        cards = usercarddata.cards["item"]
        for carddata in cards:
            if cardcode.number == carddata.number:
                starttime = carddata.startTime
                endtime = carddata.endTime
                issueid = self._lclient.getCardCurrentIssue(cardcode.number)
                if starttime < datetime.now(endtime.tzinfo) < endtime:
                    if self.config.access_levels:
                        access_levels = carddata.accessLevels["item"]
                        al_found = False
                        for al in access_levels:
                            if al.label in self.config.access_levels:
                                al_found = True
                                break
                        if not al_found:
                            raise AccessLevelViolationException(\
                                  cardcode.number, usercarddata.id.primaryID,
                                  issueid)
                    return usercarddata, issueid
                else:
                    raise CardInactiveException(cardcode.number,
                                                usercarddata.id.primaryID,
                                                issueid, starttime, endtime)
        raise UnknownCardException(cardcode.number)

    def _check_card_access_offline(self, cardcode):
        "Check card function (connection failure)"
        # Try to load cache from file
        self._card_cache.load()
        # Check card cache is loaded
        if not self._card_cache.is_empty():
            if not self._card_cache.check_card(cardcode.number):
                raise UnknownCardException(cardcode.number)
        # Card has access, but we can't get any data in offline mode
        return None, None

    def _prepare_messages(self):
        "Fill empty fields of offline messages"
        self._insert_cause_objects()
        self._insert_issue_ids()

    def _insert_cause_objects(self):
        "Fill 'causeObject' field for offline messages in queue"
        userid_cache = {}
        for message in self._message_queue:
            if message["causeObject"] == None and message["additionalFields"]:
                cardnumber = None
                # Get card number from additional fields
                try:
                    for field in message["additionalFields"]["item"]:
                        if field["name"] == "CardNumber":
                            cardnumber = field["value"]
                            break
                except KeyError:
                    continue
                if cardnumber:
                    userid = None
                    # Try to get userid from cache
                    try:
                        userid = userid_cache[cardnumber]
                        #print "Userid from cache"
                    except KeyError:
                        # Get UserCardData or raise DisconnectException
                        ucdl = self._lclient.\
                                        getUserCardDataByCardIssue(cardnumber)
                        if len(ucdl) == 1:
                            userid = ucdl[0].id.primaryID
                            userid_cache.update({cardnumber:userid})
                            #print "Userid from lyrix"
                    if userid != None:
                        message["causeObject"] = userid
                        #print "Insert userid = ", message["causeObject"]

    def _insert_issue_ids(self):
        "Fill 'Issue' additional field for offline messages in queue"
        issueid_cache = {}
        for message in self._message_queue:
            if message["additionalFields"]:
                empty_issueid = False
                # Get issue id field
                try:
                    for field in message["additionalFields"]["item"]:
                        if field["name"] == "Issue":
                            if field["value"] == None:
                                empty_issueid = True
                            break
                except KeyError:
                    continue
                if not empty_issueid:
                    continue
                cardnumber = None
                # Get card number from additional fields
                try:
                    for field in message["additionalFields"]["item"]:
                        if field["name"] == "CardNumber":
                            cardnumber = field["value"]
                            break
                except KeyError:
                    continue
                if cardnumber:
                    issueid = None
                    # Try to get issueid from cache
                    try:
                        issueid = issueid_cache[cardnumber]
                        #print "Issueid from cache"
                    except KeyError:
                        # Get IssueID or raise DisconnectException
                        issueid = self._lclient.getCardCurrentIssue(cardnumber)
                        if issueid:
                            issueid_cache.update({cardnumber:issueid})
                            #print "Issueid from lyrix"
                    # Insert IssueID value
                    if issueid:
                        for field in message["additionalFields"]["item"]:
                            if field["name"] == "Issue":
                                field["value"] = issueid
                                break
                        #print "Insert issueid = ", issueid
                    # Else remove additional field "Issue"
                    else:
                        new_f = [f for f in \
                                 message["additionalFields"]["item"] \
                                 if f["name"] != "Issue"]
                        #print "Remove field \"Issue\": ", new_f
                        message["additionalFields"]["item"] = new_f

    def _load_messages(self):
        "Load buffered messages from file"
        if self.config.messages_file == None:
            return
        try:
            msg_file = open(self.config.messages_file, "rb")
            messages = pickle.load(msg_file)
            msg_file.close()
            self._message_queue = messages
        except Exception:
            # Ignore all exceptions
            pass

    def _save_messages(self):
        "Save buffered messages to file"
        if self.config.messages_file == None:
            return
        try:
            if len(self._message_queue) > 0:
                tmp_fd, tmp_path = tempfile.mkstemp(".p", "lyrix-m-")
                tmp_file = os.fdopen(tmp_fd, "w")
                #print "TMP_FILE: ", tmp_path
                pickle.dump(self._message_queue, tmp_file,
                            pickle.HIGHEST_PROTOCOL)
                tmp_file.close()
                os.rename(tmp_path, self.config.messages_file)
                #print "%s -> %s" % (tmp_path, self.config.messages_file)
            else:
                os.unlink(self.config.messages_file)
                #print "UNLINK: ", self.config.messages_file
        except Exception:
            # Ignore all exceptions
            pass


def run_cache(config):
    "Cache service routine"
    assert isinstance(config, LyrixConfig)
    card_cache = LyrixCardCache(config.cache_livetime_m,
                                config.card_cache_file)
    sclient = LyrixClient(config.wsdl_url, config.user, config.password,
                          config.reconnect_interval_s, config.timeout)
    try:
        while True:
            if card_cache.is_expired():
                while True:
                    if not sclient.check_connection():
                        break
                    try:
                        cards = sclient.getActiveCards()
                        sclient.logoff()
                        sclient.disconnect()
                        card_cache.update(cards)
                        break
                    except DisconnectException:
                        continue
                    except WebServiceError:
                        try:
                            sclient.logoff()
                        except Exception:
                            pass
                        finally:
                            sclient.disconnect()
                        continue
            time.sleep(config.reconnect_interval_s)
    finally:
        del sclient
        del card_cache


class DisconnectException(Exception):
    "Disconnected from service"
    def __init__(self):
        super(DisconnectException, self).__init__()


class WebServiceError(Exception):
    "WebService returns error"
    def __init__(self):
        super(WebServiceError, self).__init__()


class NotLoggedOnException(Exception):
    "No active session available"
    def __init__(self):
        super(NotLoggedOnException, self).__init__()


class LyrixClient(object):
    "Lyrix SOAP client class"

    def __init__(self, url, user, password, reconnect_interval_s,
                 timeout=None):
        self.url = url
        self.user = user
        self.password = password
        self.reconnect_interval_s = reconnect_interval_s
        self.timeout = timeout
        self._client = None
        self._connected = False
        self._session = None
        self._reconnect_time = None

    def __del__(self):
        try:
            self.logoff()
        except Exception:
            pass  # Ignore all possible exceptions
        self.disconnect()

    @property
    def connected(self):
        "True if connected to service"
        return self._connected

    @property
    def session(self):
        "Session ID if logged on or None"
        return self._session

    @property
    def logged_on(self):
        "True if client has active session"
        return self._session != None

    def connect(self):
        "Connect to Lyrix service"
        try:
            if self.timeout:
                self._client = Client(self.url, timeout=self.timeout)
            else:
                self._client = Client(self.url)
            self._connected = True
        except (URLError, TransportError):
            self._connected = False
            raise DisconnectException()
        except Exception:   # Handle other exceptions as disconnect
            self._connected = False
            raise DisconnectException()

    def disconnect(self):
        "Disconnect from Lyrix service"
        del self._client
        self._client = None
        self._connected = False

    def logon(self):
        "Call Lyrix method \"logon\""
        self._check_connected()
        try:
            self._session = self._client.service.logon(self.user,
                                                       self.password)
        except (URLError, TransportError):
            self._connected = False
            raise DisconnectException()
        except WebFault:
            raise WebServiceError()
        except Exception:   # Handle other exceptions as disconnect
            self._connected = False
            raise DisconnectException()

    def logoff(self):
        "Call Lyrix method \"logoff\""
        self._check()
        try:
            self._client.service.logoff(self._session)
            self._session = None
        except (URLError, TransportError):
            self._connected = False
            raise DisconnectException()
        except WebFault:
            raise WebServiceError()
        except Exception:   # Handle other exceptions as disconnect
            self._connected = False
            raise DisconnectException()

    def check_connection(self):
        "Check connection state and try to reconnect if needed"
        if not self._connected:
            if self._reconnect_time == None:
                self._try_to_reconnect()
            else:
                delta = datetime.utcnow() - self._reconnect_time
                if delta >= timedelta(seconds=self.reconnect_interval_s):
                    self._try_to_reconnect()
        return self._connected

    def _try_to_reconnect(self):
        "Try to restore connection"
        self._reconnect_time = datetime.utcnow()
        try:
            self.connect()
            if self._session == None:
                self.logon()
            # This call checks new connection
            self.getUserCardDataByCardIssue(0)
            self._reconnect_time = None
        except DisconnectException:
            pass
        except WebServiceError:
            # Try to relogon
            try:
                self.logoff()
            except Exception:
                pass
            try:
                self.logon()
                # This call checks new connection
                self.getUserCardDataByCardIssue(0)
                self._reconnect_time = None
            except DisconnectException:
                pass
            except WebServiceError:
                # Unrecoverable error in web service!
                try:
                    self.logoff()
                except Exception:
                    pass
                self.disconnect()

    def getActiveCards(self, sort=True):
        "Call Lyrix method \"getActiveCards\""
        self._check()
        try:
            cards = self._client.service.getActiveCards(self._session, None)
            cardnumbers = []
            for cardinfo in cards:
                cardnumbers.append(long(cardinfo.number))
            if sort:
                cardnumbers.sort()
            return cardnumbers
        except (URLError, TransportError):
            self._connected = False
            raise DisconnectException()
        except WebFault:
            raise WebServiceError()
        except Exception:   # Handle other exceptions as disconnect
            self._connected = False
            raise DisconnectException()

    def getUserCardDataByCardIssue(self, cardnumber, activity=True):
        "Call Lyrix method \"getUserCardDataByCardIssue\""
        self._check()
        try:
            return self._client.service.getUserCardDataByCardIssue(\
            self._session, cardnumber, activity)
        except (URLError, TransportError):
            self._connected = False
            raise DisconnectException()
        except WebFault:
            raise WebServiceError()
        except Exception:   # Handle other exceptions as disconnect
            self._connected = False
            raise DisconnectException()

    def getCardCurrentIssue(self, cardnumber):
        "Call Lyrix method \"getCardCurrentIssue\""
        self._check()
        try:
            return self._client.service.getCardCurrentIssue(self._session,
                                                            cardnumber)
        except (URLError, TransportError):
            self._connected = False
            raise DisconnectException()
        except WebFault:
            raise WebServiceError()
        except Exception:   # Handle other exceptions as disconnect
            self._connected = False
            raise DisconnectException()

    def sendMessages(self, messages):
        "Call Lyrix method \"sendMessages\""
        self._check()
        try:
            # Send messages as a list of dicts
            self._client.service.sendMessages(self._session, messages)
        except (URLError, TransportError):
            self._connected = False
            raise DisconnectException()
        except WebFault:
            raise WebServiceError()
        except Exception:   # Handle other exceptions as disconnect
            self._connected = False
            raise DisconnectException()

    def _check(self):
        "Raise exception if client is not connected or not logged on"
        self._check_connected()
        self._check_logged_on()

    def _check_connected(self):
        "Raise DisconnectException if client is not connected"
        if not self._connected:
            raise DisconnectException()

    def _check_logged_on(self):
        "Raise NotLoggedOnException if client is not logged on"
        if self._session == None:
            raise NotLoggedOnException()
