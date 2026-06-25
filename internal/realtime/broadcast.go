package realtime

import (
	"encoding/json"

	"github.com/gorilla/websocket"
)

func Broadcast(v interface{}) {

	data, err := json.Marshal(v)

	if err != nil {
		return
	}

	for client := range Clients {

		err := client.WriteMessage(
			websocket.TextMessage,
			data,
		)

		if err != nil {

			client.Close()

			delete(
				Clients,
				client,
			)

			continue
		}
	}

	println("🔥 Broadcast Sent")
}
