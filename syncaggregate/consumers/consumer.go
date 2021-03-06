// Copyright 2017 Vector Creations Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//
// Modifications copyright (C) 2020 Finogeeks Co., Ltd

package consumers

import (
	"context"
	"github.com/finogeeks/ligase/adapter"
	"time"

	"github.com/finogeeks/ligase/plugins/message/external"
	"github.com/finogeeks/ligase/skunkworks/gomatrixserverlib"

	"github.com/finogeeks/ligase/common"
	"github.com/finogeeks/ligase/common/config"
	"github.com/finogeeks/ligase/core"
	"github.com/finogeeks/ligase/model/repos"
	"github.com/finogeeks/ligase/model/service/roomserverapi"
	"github.com/finogeeks/ligase/model/types"
	"github.com/finogeeks/ligase/skunkworks/log"
	"github.com/finogeeks/ligase/storage/model"
	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

type UtlEvent struct {
	Event        gomatrixserverlib.ClientEvent
	RelateJoined []string
	Joined       []string
}

type UtlContent struct {
	ev     *gomatrixserverlib.ClientEvent
	user   string
	result chan int64
}

type EventFeedConsumer struct {
	channel            core.IChannel
	db                 model.SyncAPIDatabase
	userTimeLine       *repos.UserTimeLineRepo
	presenceStreamRepo *repos.PresenceDataStreamRepo
	cfg                *config.Dendrite
	chanSize           uint32
	//msgChan            []chan *UtlEvent
	msgChan     []chan common.ContextMsg
	utlChanSize uint32
	utlChan     []chan common.ContextMsg
}

func NewEventFeedConsumer(
	cfg *config.Dendrite,
	store model.SyncAPIDatabase,
) *EventFeedConsumer {
	val, ok := common.GetTransportMultiplexer().GetChannel(
		cfg.Kafka.Consumer.OutputRoomEventSyncAggregate.Underlying,
		cfg.Kafka.Consumer.OutputRoomEventSyncAggregate.Name,
	)
	if ok {
		channel := val.(core.IChannel)
		s := &EventFeedConsumer{
			channel:     channel,
			db:          store,
			cfg:         cfg,
			chanSize:    64,
			utlChanSize: 64,
		}
		channel.SetHandler(s)

		return s
	}

	return nil
}

func (s *EventFeedConsumer) SetUserTimeLine(userTimeLine *repos.UserTimeLineRepo) *EventFeedConsumer {
	s.userTimeLine = userTimeLine
	return s
}

func (s *EventFeedConsumer) SetPresenceStreamRepo(presenceRepo *repos.PresenceDataStreamRepo) *EventFeedConsumer {
	s.presenceStreamRepo = presenceRepo
	return s
}

func (s *EventFeedConsumer) startWorker(msgChan chan common.ContextMsg) {
	for msg := range msgChan {
		data := msg.Msg.(*UtlEvent)
		s.onNewRoomEvent(msg.Ctx, data)
	}
}

func (s *EventFeedConsumer) startUtlWorker(utlChan chan common.ContextMsg) {
	for msg := range utlChan {
		data := msg.Msg.(*UtlContent)
		s.onInsertUserTimeLine(msg.Ctx, data)
	}
}

func (s *EventFeedConsumer) dispthInsertUserTimeLine(ctx context.Context, ev *gomatrixserverlib.ClientEvent, user string, result chan int64) {
	idx := common.CalcStringHashCode(user) % s.utlChanSize
	s.utlChan[idx] <- common.ContextMsg{Ctx: ctx, Msg: &UtlContent{
		ev:     ev,
		user:   user,
		result: result,
	}}
}

func (s *EventFeedConsumer) onInsertUserTimeLine(ctx context.Context, data *UtlContent) {
	offset, _ := s.userTimeLine.Idg.Next()
	//only for debug
	if adapter.GetDebugLevel() == adapter.DEBUG_LEVEL_DEBUG {
		delay := adapter.Random(0, 10)
		log.Infof("roomId:%s offset:%d event_id:%s user:%s sleep %ds", data.ev.RoomID, offset, data.ev.EventID, data.user, delay)
		time.Sleep(time.Duration(delay) * time.Second)
	}
	s.userTimeLine.AddP2PEv(ctx, data.ev, offset, data.user)
	data.result <- offset
}

func (s *EventFeedConsumer) Start() error {
	s.msgChan = make([]chan common.ContextMsg, s.chanSize)
	for i := uint32(0); i < s.chanSize; i++ {
		s.msgChan[i] = make(chan common.ContextMsg, 512)
		go s.startWorker(s.msgChan[i])
	}
	s.utlChan = make([]chan common.ContextMsg, s.chanSize)
	for i := uint32(0); i < s.utlChanSize; i++ {
		s.utlChan[i] = make(chan common.ContextMsg, 512)
		go s.startUtlWorker(s.utlChan[i])
	}
	//s.channel.Start()
	return nil
}

func (s *EventFeedConsumer) OnMessage(ctx context.Context, topic string, partition int32, data []byte, rawMsg interface{}) {
	var output roomserverapi.OutputEvent
	if err := json.Unmarshal(data, &output); err != nil {
		log.Errorw("sync aggregate: message parse failure", log.KeysAndValues{"error", err})
		return
	}

	log.Infow("sync aggregate received data", log.KeysAndValues{"type", output.Type, "topic", topic})

	switch output.Type {
	case roomserverapi.OutputTypeNewRoomEvent:
		utlEvent := &UtlEvent{
			Event:        output.NewRoomEvent.Event,
			RelateJoined: []string{},
			Joined:       []string{},
		}
		for _, user := range output.NewRoomEvent.Joined {
			utlEvent.Joined = append(utlEvent.Joined, user)
			if common.IsRelatedRequest(user, s.cfg.MultiInstance.Instance, s.cfg.MultiInstance.Total, false) {
				utlEvent.RelateJoined = append(utlEvent.RelateJoined, user)
			}
		}
		if len(utlEvent.RelateJoined) > 0 || (len(utlEvent.RelateJoined) <= 0 && utlEvent.Event.Type == "m.room.member") {
			log.Infof("sync aggregate received data instance:%d IsRelatedRequest event_id:%s room:%s RelateJoined:%v", s.cfg.MultiInstance.Instance, utlEvent.Event.EventID, utlEvent.Event.RoomID, utlEvent.RelateJoined)
			idx := common.CalcStringHashCode(utlEvent.Event.RoomID) % s.chanSize
			s.msgChan[idx] <- common.ContextMsg{Ctx: ctx, Msg: utlEvent}
		} else {
			log.Infof("sync aggregate received data instance:%d not IsRelatedRequest and not m.room.member event_id:%s room:%s joined:%v", s.cfg.MultiInstance.Instance, utlEvent.Event.EventID, utlEvent.Event.RoomID, output.NewRoomEvent.Joined)
		}
	default:
		log.Debugw("sync aggregate: ignoring unknown output type", log.KeysAndValues{"type", output.Type})
	}
}

func (s *EventFeedConsumer) onNewRoomEvent(
	ctx context.Context, msg *UtlEvent,
) error {
	defer func() {
		if e := recover(); e != nil {
			stack := common.PanicTrace(4)
			log.Panicf("%v\n%s\n", e, stack)
		}
	}()
	log.Infof("onNewRoomEvent.addUserTimeLineEvent roomID:%s eventID:%s msg.RelateJoined len:%d msg.Joined len:%d", msg.Event.RoomID, msg.Event.EventID, len(msg.RelateJoined), len(msg.Joined))
	s.addUserTimeLineEvent(ctx, &msg.Event, msg.RelateJoined, msg.Joined)
	return nil
}

func (s *EventFeedConsumer) addUserTimeLineEvent(ctx context.Context, ev *gomatrixserverlib.ClientEvent, relateUsers []string, users []string) {
	var updateProfileUser map[string]map[string]struct{}
	//offset, _ := s.userTimeLine.Idg.Next()
	if ev.Type == "m.room.member" && ev.StateKey != nil {
		member := external.MemberContent{}
		json.Unmarshal(ev.Content, &member)
		if member.Membership != "join" {
			if common.IsRelatedRequest(*ev.StateKey, s.cfg.MultiInstance.Instance, s.cfg.MultiInstance.Total, false) {
				bs := time.Now().UnixNano() / 1000000
				//s.userTimeLine.AddP2PEv(ctx, ev, offset, *ev.StateKey)
				result := make(chan int64)
				s.dispthInsertUserTimeLine(ctx, ev, *ev.StateKey, result)
				offset := <-result
				spend := time.Now().UnixNano()/1000000 - bs
				log.Infof("m.room.member not join add to timeline roomId:%s offset:%d event_id:%s user_id:%s spend:%dms", ev.RoomID, offset, ev.EventID, *ev.StateKey, spend)
			}
		} else {
			updateProfileUser = map[string]map[string]struct{}{}
			domain, _ := common.DomainFromID(*ev.StateKey)
			isSelfDomain := common.CheckValidDomain(domain, s.cfg.Matrix.ServerName)
			bs := time.Now().UnixNano() / 1000000
			for _, member := range relateUsers {
				hasLoad, hasFriendship := s.userTimeLine.AddFriendShip(member, *ev.StateKey)
				domainCheck, _ := common.DomainFromID(member)
				isSelfDomainCheck := common.CheckValidDomain(domainCheck, s.cfg.Matrix.ServerName)
				if (!hasLoad || !hasFriendship) && isSelfDomainCheck != isSelfDomain {
					var domainA, userB string
					if isSelfDomain {
						domainA = domainCheck
						userB = *ev.StateKey
					} else {
						domainA = domain
						userB = member
					}
					m, ok := updateProfileUser[domainA]
					if !ok {
						m = map[string]struct{}{}
						updateProfileUser[domainA] = m
					}
					m[userB] = struct{}{}
				}
			}
			if common.IsRelatedRequest(*ev.StateKey, s.cfg.MultiInstance.Instance, s.cfg.MultiInstance.Total, false) {
				for _, member := range users {
					s.userTimeLine.AddFriendShip(*ev.StateKey, member)
				}
			}
			spend := time.Now().UnixNano()/1000000 - bs
			log.Infof("m.room.member join add to add friend ship roomId:%s event_id:%s user_id:%s spend:%dms", ev.RoomID, ev.EventID, *ev.StateKey, spend)
		}
	}
	for _, user := range relateUsers {
		bs := time.Now().UnixNano() / 1000000
		//s.userTimeLine.AddP2PEv(ctx, ev, offset, user)
		result := make(chan int64)
		s.dispthInsertUserTimeLine(ctx, ev, user, result)
		offset := <-result
		spend := time.Now().UnixNano()/1000000 - bs
		log.Infof("m.room.member not join add to timeline roomId:%s offset:%d event_id:%s user_id:%s spend:%dms", ev.RoomID, offset, ev.EventID, user, spend)
	}
	if updateProfileUser != nil {
		for domain, users := range updateProfileUser {
			for user := range users {
				feed := s.presenceStreamRepo.GetHistoryByUserID(user)
				if feed != nil {
					senderDomain, _ := common.DomainFromID(user)

					var presenceEvent gomatrixserverlib.ClientEvent
					var presenceContent types.PresenceJSON
					json.Unmarshal(feed.DataStream.Content, &presenceEvent)
					json.Unmarshal(presenceEvent.Content, &presenceContent)

					fedProfile := types.ProfileContent{
						UserID:      user,
						DisplayName: presenceContent.DisplayName,
						AvatarUrl:   presenceContent.AvatarURL,
						Presence:    presenceContent.Presence,
						UserName:    presenceContent.UserName,
						JobNumber:   presenceContent.JobNumber,
						Mobile:      presenceContent.Mobile,
						Landline:    presenceContent.Landline,
						Email:       presenceContent.Email,
					}
					content, _ := json.Marshal(fedProfile)
					log.Infof("send profile to new domain, user:%s, domain:%s, profile:%s", user, domain, content)
					edu := gomatrixserverlib.EDU{
						Type:        "profile",
						Origin:      senderDomain,
						Destination: domain,
						Content:     content,
					}
					func() {
						span, _ := common.StartSpanFromContext(ctx, s.cfg.Kafka.Producer.FedEduUpdate.Name)
						defer span.Finish()
						common.ExportMetricsBeforeSending(span, s.cfg.Kafka.Producer.FedEduUpdate.Name,
							s.cfg.Kafka.Producer.FedEduUpdate.Underlying)
						common.GetTransportMultiplexer().SendWithRetry(
							s.cfg.Kafka.Producer.FedEduUpdate.Underlying,
							s.cfg.Kafka.Producer.FedEduUpdate.Name,
							&core.TransportPubMsg{
								Keys:    []byte(user),
								Obj:     edu,
								Headers: common.InjectSpanToHeaderForSending(span),
							})
					}()
				}
			}
		}
	}
}
