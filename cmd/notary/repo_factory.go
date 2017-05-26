package main

import (
	"github.com/spf13/viper"

	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/docker/notary"
	"github.com/docker/notary/auth/grpc"
	"github.com/docker/notary/client"
	"github.com/docker/notary/client_api/api"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/utils"
)

const remoteConfigField = "api"

type repoFactory func(gun data.GUN) (client.Repository, error)

// ConfigureRepo Note: [probably] onlineOperation is false when operation is performed locally by the API client,
// it is true when performing by the CLI client, and require cooperation by the API client
func ConfigureRepo(v *viper.Viper, retriever notary.PassRetriever, onlineOperation bool) repoFactory {
	localRepo := func(gun data.GUN) (client.Repository, error) {
		logrus.Debug("using local repo")
		var rt http.RoundTripper
		trustPin, err := getTrustPinning(v)
		if err != nil {
			return nil, err
		}
		if onlineOperation {
			rt, err = getTransport(v, gun, admin)
			if err != nil {
				return nil, err
			}
		}
		return client.NewFileCachedNotaryRepository(
			v.GetString("trust_dir"),
			gun,
			getRemoteTrustServer(v),
			rt,
			retriever,
			trustPin,
		)
	}

	remoteRepo := func(gun data.GUN) (client.Repository, error) {
		logrus.Debug("using remote repo")
		conn, err := utils.GetGRPCClient(
			v,
			remoteConfigField,
			grpcauth.NewCredStore(&passwordStore{false}, nil, nil),
		)
		if err != nil {
			return nil, err
		}
		return api.NewClient(conn, gun), nil
	}

	if v.IsSet(remoteConfigField) {
		return remoteRepo
	}
	return localRepo
}
