package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/go-redis/redis"
	"github.com/gorilla/pat"
	"github.com/gorilla/sessions"
	random_project_generator "github.com/kevinburke/go-random-project-generator"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
)

var host string
var count = 0
var clientKey string
var clientSecret string
var redirect string
var domain string

func main() {
	listenport := flag.String("listen", ":25565", "The port / IP combo you want to listen on")
	host = *flag.String("host", "minecraft:25565", "host of server")
	clientKey = *flag.String("oauth_key", "", "OAuth key")
	clientSecret = *flag.String("oauth_secret", "", "OAuth Secret")
	domain = *flag.String("domain", "NOTSETUP", "Domain")
	redirect = *flag.String("oauth_redirect", "", "OAuth Redirect")

	flag.Parse()

	client := redis.NewClient(&redis.Options{
		Addr:     "redis:6379",
		Password: "",
		DB:       0,
	})

	go minecraftServer(*listenport, client)

	httpServer(client)
}

func httpServer(client *redis.Client) {

	key := "pizza" // Replace with your SESSION_SECRET or similar
	maxAge := 86400
	isProd := false

	store := sessions.NewCookieStore([]byte(key))
	store.MaxAge(maxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true // HttpOnly should always be enabled
	store.Options.Secure = isProd

	gothic.Store = store

	goth.UseProviders(
		google.New(clientKey, clientSecret, redirect, "email", "profile"),
	)

	p := pat.New()
	p.Get("/auth/{provider}/callback", func(res http.ResponseWriter, req *http.Request) {
		session, _ := store.Get(req, "mc")
		username := session.Values["user"].(string)
		user, err := gothic.CompleteUserAuth(res, req)
		if err != nil {
			fmt.Fprintln(res, err)
			return
		}

		io.WriteString(res, fmt.Sprintf("Email %s & Username %s", user.Email, username))
		client.Set("user/"+username, user.Email, 0)
	})

	p.Get("/auth/{loginCode}", func(res http.ResponseWriter, req *http.Request) {
		loginCode := req.URL.Query().Get(":loginCode")
		val, err := client.Get("auth/" + loginCode).Result()
		if err != nil {
			io.WriteString(res, fmt.Sprintf("Auth key not found"))
			return
		}
		client.Del("auth/" + loginCode)
		{
			session, _ := store.Get(req, "mc")
			session.Values["user"] = val
			session.Save(req, res)
		}

		log.Println("Login to", loginCode, "by user", val)
		q := req.URL.Query()
		q.Add("provider", "google")
		req.URL.RawQuery = q.Encode()
		url, err := gothic.GetAuthURL(res, req)
		if err != nil {
			res.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(res, err)
			return
		}

		http.Redirect(res, req, url, http.StatusTemporaryRedirect)
	})

	log.Println("listening on localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", p))
}

func minecraftServer(listenport string, client *redis.Client) {
	lis, err := net.Listen("tcp", listenport)
	LazyHandle(err)

	for {
		con, err := lis.Accept()
		if err != nil {
			log.Printf("Huh. Unable to accept a connection :( (%s)", err.Error())
			continue
		}
		go HandleConnection(con, client)
	}
}

func LazyHandle(err error) {
	if err != nil {
		log.Fatal(err.Error())
	}
}

func HandleConnection(con net.Conn, client *redis.Client) {
	defer con.Close()
	packet_id := uint(0)
	data := []byte{}
	packet := []byte{}
	r := bufio.NewReader(con)

	// Read incoming packet
	packet_id, data, packet = ReadPacket(r)
	i := 0

	if packet_id == 0x00 {
		// Handshake
		log.Printf("<%s> Received handshake", con.RemoteAddr().String())

		// Protocol version
		protocol, bytes_read := ReadVarint(data[i:])
		if bytes_read <= 0 {
			log.Printf("<%s> An error occured when reading protocol version of handshake packet: %d", con.RemoteAddr().String(), bytes_read)
			return
		}
		i += bytes_read

		// Address
		_, bytes_read = ReadString(data[i:])
		if bytes_read <= 0 {
			log.Printf("<%s> An error occured when reading server address of handshake packet: %d", con.RemoteAddr().String(), bytes_read)
			return
		}
		i += bytes_read

		// Port
		//port := binary.BigEndian.Uint16(data[i:i + 2])
		i += 2

		// Next state
		next_state, bytes_read := ReadVarint(data[i:])
		if bytes_read <= 0 {
			log.Printf("<%s> An error occured when reading next state of handshake packet: %d", con.RemoteAddr().String(), bytes_read)
			return
		}

		if next_state == 0x01 {
			log.Printf("<%s> Received server list request", con.RemoteAddr().String())

			// Consume request packet
			packet_id2, data2, _ := ReadPacket(r)
			if packet_id2 == 0x00 && len(data2) == 0 {
				log.Printf("<%s> Received request", con.RemoteAddr().String())

				msg := map[string]interface{}{
					"version": map[string]interface{}{
						"name":     "server",
						"protocol": protocol,
					},
					"players": map[string]interface{}{
						"max":    20,
						"online": count,
					},
					"description": map[string]interface{}{
						"text": "UMass Makerspace Minecraft Server",
					},
				}
				server_list_json, _ := json.Marshal(msg)
				response := MakePacket(0x00, MakeString(string(server_list_json)))
				con.Write(response)
				log.Printf("<%s> Sent response", con.RemoteAddr().String())
			}

			// Prepare for ping request
			packet_id2, _, packet2 := ReadPacket(r)
			i = 0
			if packet_id2 == 0x01 {
				// Ping
				log.Printf("<%s> Received ping", con.RemoteAddr().String())

				// Send same packet back to the client
				con.Write(packet2)
				log.Printf("<%s> Sent pong", con.RemoteAddr().String())

				// Done
				return
			}

		} else if next_state == 0x02 {
			_, data, packet2 := ReadPacket(r)
			i = 0
			player_name, r := ReadString(data[i:])
			i += r

			authpath := random_project_generator.GenerateNumber(1)
			_, loggedIn := client.Get("user/" + player_name).Result()
			if loggedIn != nil {
				err := client.Set("auth/"+authpath, player_name, 0).Err()
				if err != nil {
					fmt.Println(err)
				}
				log.Printf("<%s> Player tried logging in %s, sent to auth %s", con.RemoteAddr().String(), player_name, authpath)
				con.Write(MakePacket(0x00, MakeString(fmt.Sprintf("\"%s is not associated with a UMass email. Please login at https://%s/auth/%s\"", player_name, domain, authpath))))
				return
			}

			log.Printf("<%s> Player logging in %s", con.RemoteAddr().String(), player_name)
			Scon, err := net.Dial("tcp", host)
			if err != nil {
				con.Write(MakePacket(0x00, MakeString(fmt.Sprintf("\"Failed to connect to server: %v\"", err))))
				return
			}
			count++
			defer Scon.Close()
			Scon.Write(packet)
			Scon.Write(packet2)
			go io.Copy(Scon, con)
			io.Copy(con, Scon)

			log.Println("Player disconnected")
			count--
		} else {
			log.Println("HUH")
		}
	}
}

func ReadPacket(r *bufio.Reader) (uint, []byte, []byte) {
	length, err := binary.ReadUvarint(r)
	if err != nil {
		if err != io.EOF {
			log.Printf("An error occured when reading packet length: %d", err)
		}
		return 0, nil, nil
	}
	packet := make([]byte, length)
	bytes_read, _ := io.ReadFull(r, packet)

	if int(length) != bytes_read {
		full_packet := append(MakeVarint(int(length)), packet...)
		log.Printf("Received unknown packet, proceeding as legacy packet 0x%x", length)
		return uint(length), packet, full_packet
	}

	// Read packet id
	packet_id, bytes_read := ReadVarint(packet)
	if bytes_read <= 0 {
		log.Printf("An error occured when reading packet id of packet: %d", bytes_read)
		return 0, nil, nil
	}
	i := bytes_read

	if length == 0 {
		return uint(packet_id), []byte{}, append(MakeVarint(int(length)), packet...)
	} else {
		return uint(packet_id), packet[i:], append(MakeVarint(int(length)), packet...)
	}
}

func MakePacket(packet_id int, data []byte) []byte {
	packet := append(MakeVarint(packet_id), data...)
	return append(MakeVarint(len(packet)), packet...)
}

func ReadVarint(data []byte) (int, int) {
	value, bytes_read := binary.Uvarint(data)
	if bytes_read <= 0 {
		log.Printf("An error occured while reading varint: %d", bytes_read)
		return 0, bytes_read
	}
	return int(value), bytes_read
}

func MakeVarint(value int) []byte {
	temp := make([]byte, 10)
	bytes_written := binary.PutUvarint(temp, uint64(value))
	return temp[:bytes_written]
}

func ReadString(data []byte) (string, int) {
	length, bytes_read := ReadVarint(data)
	if bytes_read <= 0 {
		log.Printf("An error occured while reading string: %d", bytes_read)
		return "", bytes_read
	}
	return string(data[bytes_read : bytes_read+length]), bytes_read + length
}

func MakeString(str string) []byte {
	data := []byte(str)
	return append(MakeVarint(len(data)), data...)
}
