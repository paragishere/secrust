package realtime

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var Clients = make(map[*websocket.Conn]bool)

var Upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func HandleWS(c *gin.Context) {

	conn, err := Upgrader.Upgrade(
		c.Writer,
		c.Request,
		nil,
	)

	if err != nil {
		return
	}

	Clients[conn] = true

	println("✅ New WebSocket Client Connected")

	for {

		if _, _, err := conn.ReadMessage(); err != nil {

			delete(
				Clients,
				conn,
			)

			conn.Close()

			println("❌ Client Disconnected")

			break
		}
	}
}
