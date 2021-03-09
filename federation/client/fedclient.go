// Copyright (C) 2020 Finogeeks Co., Ltd
//
// This program is free software: you can redistribute it and/or  modify
// it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package client

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/finogeeks/ligase/common"
	"github.com/finogeeks/ligase/skunkworks/gomatrixserverlib"
	"github.com/finogeeks/ligase/skunkworks/log"
)

var (
	FedClients  sync.Map
	loading     sync.Map
	Certs       *sync.Map
	FedDomains  *common.FedDomains
	localDomain string
)

type FedClientWrap struct {
	clients sync.Map
	Client  *gomatrixserverlib.FederationClient
}

func SetCerts(c *sync.Map) {
	Certs = c
}

func SetFedDomains(ld string, d *common.FedDomains) {
	localDomain = ld
	FedDomains = d
}

func OnFedDomainsUpdate(domains []common.FedDomainInfo) {
	FedDomains.OnFedDomainsUpdate(domains)
	ReNewFedClient(localDomain)
}

func NewFedClient(serverName string) *FedClientWrap {
	fed := &FedClientWrap{}

	enable, _ := Certs.Load("httpsCliEnable")
	rootCA, _ := Certs.Load("rootCA")
	keyPem, _ := Certs.Load("serverKey")
	certPem, _ := Certs.Load("serverCert")
	revoked, _ := Certs.Load("revoked")
	if rootCA == nil {
		rootCA = ""
		keyPem = ""
		certPem = ""
	}
	if enable == nil {
		enable = false
	}
	if revoked == nil {
		revoked = false
	}

	// in case of revoking cert
	if enable.(bool) == true && certPem.(string) == "" {
		// FIXME: need panic here ???
		log.Warnf("fed client should send through https but cannot load cert!!!")
	}
	if revoked.(bool) == true {
		log.Warnf("cert is revoked or expired")
	}

	domainInfos := FedDomains.GetAllDomainInfos()
	for _, v := range domainInfos {
		destination, ok := FedDomains.GetDomainHost(v.Domain)
		if !ok {
			log.Warnf("Destination not found for domain: %s\n", v.Domain)
		}

		log.Infow("=================================", log.KeysAndValues{"v.Domain", v.Domain, "destination", destination, "v.Scheme", v.Scheme})
		client := new(gomatrixserverlib.FederationClient)
		if v.Scheme == "http" {
			client = gomatrixserverlib.NewFederationClient(gomatrixserverlib.ServerName(v.Domain), "", nil, "", "", "")
		} else {
			client = gomatrixserverlib.NewFederationClient(
				gomatrixserverlib.ServerName(v.Domain), "", nil, rootCA.(string), certPem.(string), keyPem.(string))
		}

		fed.clients.Store(destination, client)
	}

	return fed
}

func ReNewFedClient(serverName string) {
	// FedClients.Delete(serverName)

	_, err := blockReNew(serverName, time.Millisecond*5000)
	log.Infof("---------------------- renew fed client of %s, err: %v", serverName, err)
}

func GetFedClient(serverName string) (*FedClientWrap, error) {
	val, ok := FedClients.Load(serverName)
	if ok {
		return val.(*FedClientWrap), nil
	}

	fedClient, err := blockReNew(serverName, time.Millisecond*3000)
	log.Infof("---------------------- get fed client of %s, err: %v", serverName, err)
	return fedClient, err
}

func blockReNew(serverName string, timeout time.Duration) (*FedClientWrap, error) {
	start := time.Now()
	for {
		if _, ok := loading.Load(serverName); !ok {
			loading.Store(serverName, true)
			fedCli := NewFedClient(serverName)
			FedClients.Store(serverName, fedCli)
			loading.Delete(serverName)

			return fedCli, nil
		} else {
			time.Sleep(time.Millisecond * 50)
		}

		elapsed := time.Since(start)
		if elapsed >= timeout {
			return nil, errors.New("wating for new fed client timeout")
		}
	}
}

func checkCert() (bool, error) {
	msg := ""
	revoked, _ := Certs.Load("revoked")
	if revoked == nil {
		return true, nil
	}
	if revoked.(bool) == true {
		msg = "fed client send failed, cert has revoked or expired"
		log.Warnf(msg)
	}
	return !revoked.(bool), errors.New(msg)
}

func (fed *FedClientWrap) GetFedClientByDestination(des string) (*gomatrixserverlib.FederationClient, error) {
	if client, ok := fed.clients.Load(des); ok {
		return client.(*gomatrixserverlib.FederationClient), nil
	}

	return nil, errors.New("Fed client not found")
}

func (fed *FedClientWrap) LookupRoomAlias(
	ctx context.Context, destination, alias string,
) (res gomatrixserverlib.RespDirectory, err error) {
	if ok, err := checkCert(); !ok {
		return gomatrixserverlib.RespDirectory{}, err
	}

	client, err := fed.GetFedClientByDestination(destination)
	if err != nil {
		return gomatrixserverlib.RespDirectory{}, err
	}

	return client.LookupRoomAlias(ctx, gomatrixserverlib.ServerName(destination), alias)
}

func (fed *FedClientWrap) LookupProfile(
	ctx context.Context, destination, userID string,
) (res gomatrixserverlib.RespProfile, err error) {
	if ok, err := checkCert(); !ok {
		return gomatrixserverlib.RespProfile{}, err
	}

	client, err := fed.GetFedClientByDestination(destination)
	if err != nil {
		return gomatrixserverlib.RespProfile{}, err
	}

	return client.LookupProfile(ctx, gomatrixserverlib.ServerName(destination), userID)
}

func (fed *FedClientWrap) LookupAvatarURL(
	ctx context.Context, destination, userID string,
) (res gomatrixserverlib.RespAvatarURL, err error) {
	if ok, err := checkCert(); !ok {
		return gomatrixserverlib.RespAvatarURL{}, err
	}

	client, err := fed.GetFedClientByDestination(destination)
	if err != nil {
		return gomatrixserverlib.RespAvatarURL{}, err
	}

	return client.LookupAvatarURL(ctx, gomatrixserverlib.ServerName(destination), userID)
}

func (fed *FedClientWrap) LookupDisplayName(
	ctx context.Context, destination, userID string,
) (res gomatrixserverlib.RespDisplayname, err error) {
	if ok, err := checkCert(); !ok {
		return gomatrixserverlib.RespDisplayname{}, err
	}

	client, err := fed.GetFedClientByDestination(destination)
	if err != nil {
		return gomatrixserverlib.RespDisplayname{}, err
	}

	return client.LookupDisplayname(ctx, gomatrixserverlib.ServerName(destination), userID)
}

func (fed *FedClientWrap) LookupState(
	ctx context.Context, destination, roomID, eventID string,
) (res gomatrixserverlib.RespState, err error) {
	if ok, err := checkCert(); !ok {
		return gomatrixserverlib.RespState{}, err
	}

	client, err := fed.GetFedClientByDestination(destination)
	if err != nil {
		return gomatrixserverlib.RespState{}, err
	}

	return client.LookupState(ctx, gomatrixserverlib.ServerName(destination), roomID, eventID)
}

func (fed *FedClientWrap) Download(
	ctx context.Context, destination, domain, mediaID, width, method, fileType string, cb func(response *http.Response) error,
) (err error) {
	if ok, err := checkCert(); !ok {
		return err
	}

	client, err := fed.GetFedClientByDestination(destination)
	if err != nil {
		return err
	}

	return client.Download(ctx, gomatrixserverlib.ServerName(destination), domain, mediaID, width, method, fileType, cb)
}

func (fed *FedClientWrap) LookupMediaInfo(
	ctx context.Context, destination, mediaID, userID string,
) (res gomatrixserverlib.RespMediaInfo, err error) {
	if ok, err := checkCert(); !ok {
		return gomatrixserverlib.RespMediaInfo{}, err
	}

	client, err := fed.GetFedClientByDestination(destination)
	if err != nil {
		return gomatrixserverlib.RespMediaInfo{}, err
	}

	return client.LookupMediaInfo(ctx, gomatrixserverlib.ServerName(destination), mediaID, userID)
}

func (fed *FedClientWrap) Backfill(
	ctx context.Context, s gomatrixserverlib.ServerName, domain, roomID string,
	limit int, eventIDs []string, dir string,
) (res gomatrixserverlib.BackfillResponse, err error) {
	if ok, err := checkCert(); !ok {
		return gomatrixserverlib.BackfillResponse{}, err
	}

	client, err := fed.GetFedClientByDestination(string(s))
	if err != nil {
		return gomatrixserverlib.BackfillResponse{}, err
	}

	return client.Backfill(ctx, s, domain, roomID, limit, eventIDs, dir)
}

func (fed *FedClientWrap) SendTransaction(
	ctx context.Context, t gomatrixserverlib.Transaction,
) (res gomatrixserverlib.RespSend, err error) {
	if ok, err := checkCert(); !ok {
		return gomatrixserverlib.RespSend{}, err
	}

	client, err := fed.GetFedClientByDestination(string(t.Destination))
	if err != nil {
		return gomatrixserverlib.RespSend{}, err
	}

	log.Infow("=================================", log.KeysAndValues{"client", client})
	return client.SendTransaction(ctx, t)
}

func (fed *FedClientWrap) LookupUserInfo(
	ctx context.Context, destination, userID string,
) (res gomatrixserverlib.RespUserInfo, err error) {
	if ok, err := checkCert(); !ok {
		return gomatrixserverlib.RespUserInfo{}, err
	}

	client, err := fed.GetFedClientByDestination(destination)
	if err != nil {
		return gomatrixserverlib.RespUserInfo{}, err
	}

	return client.LookupUserInfo(ctx, gomatrixserverlib.ServerName(destination), userID)
}

func (fed *FedClientWrap) MakeJoin(
	ctx context.Context, s gomatrixserverlib.ServerName, roomID, userID string, ver []string,
) (res gomatrixserverlib.RespMakeJoin, err error) {
	if ok, err := checkCert(); !ok {
		return gomatrixserverlib.RespMakeJoin{}, err
	}

	client, err := fed.GetFedClientByDestination(string(s))
	if err != nil {
		return gomatrixserverlib.RespMakeJoin{}, err
	}

	return client.MakeJoin(ctx, s, roomID, userID, ver)
}

func (fed *FedClientWrap) SendJoin(
	ctx context.Context, s gomatrixserverlib.ServerName, roomID, eventID string, event gomatrixserverlib.Event,
) (res gomatrixserverlib.RespSendJoin, err error) {
	if ok, err := checkCert(); !ok {
		return gomatrixserverlib.RespSendJoin{}, err
	}

	client, err := fed.GetFedClientByDestination(string(s))
	if err != nil {
		return gomatrixserverlib.RespSendJoin{}, err
	}

	return client.SendJoin(ctx, s, roomID, eventID, event)
}

func (fed *FedClientWrap) SendInvite(
	ctx context.Context, destination string, event gomatrixserverlib.Event,
) (res gomatrixserverlib.RespInvite, err error) {
	if ok, err := checkCert(); !ok {
		return gomatrixserverlib.RespInvite{}, err
	}

	client, err := fed.GetFedClientByDestination(destination)
	if err != nil {
		return gomatrixserverlib.RespInvite{}, err
	}

	return client.SendInvite(ctx, gomatrixserverlib.ServerName(destination), event)
}

func (fed *FedClientWrap) MakeLeave(
	ctx context.Context, s gomatrixserverlib.ServerName, roomID, userID string,
) (res gomatrixserverlib.RespMakeLeave, err error) {
	if ok, err := checkCert(); !ok {
		return gomatrixserverlib.RespMakeLeave{}, err
	}

	client, err := fed.GetFedClientByDestination(string(s))
	if err != nil {
		return gomatrixserverlib.RespMakeLeave{}, err
	}

	return client.MakeLeave(ctx, s, roomID, userID)
}

func (fed *FedClientWrap) SendLeave(
	ctx context.Context, s gomatrixserverlib.ServerName, roomID, eventID string, event gomatrixserverlib.Event,
) (res gomatrixserverlib.RespSendLeave, err error) {
	if ok, err := checkCert(); !ok {
		return gomatrixserverlib.RespSendLeave{}, err
	}

	client, err := fed.GetFedClientByDestination(string(s))
	if err != nil {
		return gomatrixserverlib.RespSendLeave{}, err
	}

	return client.SendLeave(ctx, s, roomID, eventID, event)
}
