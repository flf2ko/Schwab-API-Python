package schwabdev

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Stream 结构体用于处理Schwab API的流数据
type Stream struct {
	client        *Client
	conn          *websocket.Conn
	streamerInfo  map[string]interface{}
	requestID     int
	active        bool
	subscriptions map[string]map[string][]string
	mu            sync.Mutex
}

// NewStream 创建一个新的Stream实例
func NewStream(client *Client) *Stream {
	return &Stream{
		client:        client,
		subscriptions: make(map[string]map[string][]string),
	}
}

// Start 启动流
func (s *Stream) Start(receiver func([]byte)) error {
	if s.active {
		if s.client.Verbose {
			fmt.Println("[Schwabdev] Stream already active.")
		}
		return nil
	}

	// 获取streamer信息
	resp, err := s.client.Preferences()
	if err != nil {
		return fmt.Errorf("failed to get preferences: %v", err)
	}
	defer resp.Body.Close()

	var preferencesResp struct {
		StreamerInfo []map[string]interface{} `json:"streamerInfo"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&preferencesResp); err != nil {
		return fmt.Errorf("failed to decode preferences response: %v", err)
	}

	if len(preferencesResp.StreamerInfo) == 0 {
		return fmt.Errorf("no streamer info found")
	}
	s.streamerInfo = preferencesResp.StreamerInfo[0]

	// 连接到WebSocket服务器
	u, err := url.Parse(s.streamerInfo["streamerSocketUrl"].(string))
	if err != nil {
		return fmt.Errorf("invalid streamer socket URL: %v", err)
	}

	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("dial error: %v", err)
	}
	s.conn = c

	// 发送登录请求
	loginPayload := s.basicRequest("ADMIN", "LOGIN", map[string]interface{}{
		"Authorization":          s.client.AccessToken,
		"SchwabClientChannel":    s.streamerInfo["schwabClientChannel"],
		"SchwabClientFunctionId": s.streamerInfo["schwabClientFunctionId"],
	})
	if err := s.conn.WriteJSON(loginPayload); err != nil {
		return fmt.Errorf("failed to send login request: %v", err)
	}

	// 读取登录响应
	_, message, err := s.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read login response: %v", err)
	}
	receiver(message)

	s.active = true

	// 发送订阅请求
	for service, subs := range s.subscriptions {
		var requests []interface{}
		for key, fields := range subs {
			requests = append(requests, s.basicRequest(service, "ADD", map[string]interface{}{
				"keys":   key,
				"fields": strings.Join(fields, ","),
			}))
		}
		if len(requests) > 0 {
			if err := s.conn.WriteJSON(map[string]interface{}{"requests": requests}); err != nil {
				return fmt.Errorf("failed to send subscription requests: %v", err)
			}
			_, message, err := s.conn.ReadMessage()
			if err != nil {
				return fmt.Errorf("failed to read subscription response: %v", err)
			}
			receiver(message)
		}
	}

	// 启动主监听循环
	go func() {
		for {
			_, message, err := s.conn.ReadMessage()
			if err != nil {
				s.active = false
				fmt.Printf("[Schwabdev] Stream connection lost: %v\n", err)
				return
			}
			receiver(message)
		}
	}()

	return nil
}

// Stop 停止流
func (s *Stream) Stop() error {
	if !s.active {
		return nil
	}

	s.requestID++
	logoutPayload := s.basicRequest("ADMIN", "LOGOUT", nil)
	if err := s.conn.WriteJSON(logoutPayload); err != nil {
		return fmt.Errorf("failed to send logout request: %v", err)
	}

	s.active = false
	return s.conn.Close()
}

// Send 发送请求到流
func (s *Stream) Send(requests interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return fmt.Errorf("stream is not active")
	}

	return s.conn.WriteJSON(map[string]interface{}{"requests": requests})
}

// basicRequest 创建基本请求
func (s *Stream) basicRequest(service, command string, parameters map[string]interface{}) map[string]interface{} {
	s.requestID++
	request := map[string]interface{}{
		"service":                strings.ToUpper(service),
		"command":                strings.ToUpper(command),
		"requestid":              s.requestID,
		"SchwabClientCustomerId": s.streamerInfo["schwabClientCustomerId"],
		"SchwabClientCorrelId":   s.streamerInfo["schwabClientCorrelId"],
	}
	if parameters != nil {
		request["parameters"] = parameters
	}
	return request
}

// Subscribe 订阅特定服务的数据
func (s *Stream) Subscribe(service, keys string, fields []string) {
	s.mu.Lock()
	defer s.mu.Lock()

	if s.subscriptions[service] == nil {
		s.subscriptions[service] = make(map[string][]string)
	}
	s.subscriptions[service][keys] = fields

	if s.active {
		request := s.basicRequest(service, "ADD", map[string]interface{}{
			"keys":   keys,
			"fields": strings.Join(fields, ","),
		})
		if err := s.conn.WriteJSON(map[string]interface{}{"requests": []interface{}{request}}); err != nil {
			fmt.Printf("[Schwabdev] Failed to send subscription request: %v\n", err)
		}
	}
}

// Unsubscribe 取消订阅特定服务的数据
func (s *Stream) Unsubscribe(service, keys string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.subscriptions[service] != nil {
		delete(s.subscriptions[service], keys)
	}

	if s.active {
		request := s.basicRequest(service, "REMOVE", map[string]interface{}{
			"keys": keys,
		})
		if err := s.conn.WriteJSON(map[string]interface{}{"requests": []interface{}{request}}); err != nil {
			fmt.Printf("[Schwabdev] Failed to send unsubscription request: %v\n", err)
		}
	}
}

// LevelOneEquities 创建Level One Equities请求
func (s *Stream) LevelOneEquities(keys []string, fields []string, command string) map[string]interface{} {
	return s.basicRequest("LEVELONE_EQUITIES", command, map[string]interface{}{
		"keys":   strings.Join(keys, ","),
		"fields": strings.Join(fields, ","),
	})
}

// LevelOneOptions 创建Level One Options请求
func (s *Stream) LevelOneOptions(keys []string, fields []string, command string) map[string]interface{} {
	return s.basicRequest("LEVELONE_OPTIONS", command, map[string]interface{}{
		"keys":   strings.Join(keys, ","),
		"fields": strings.Join(fields, ","),
	})
}

// StartAuto 自动启动流
func (s *Stream) StartAuto(receiver func([]byte), afterHours, preHours bool) {
	start := time.Date(0, 1, 1, 13, 29, 0, 0, time.UTC)
	end := time.Date(0, 1, 1, 20, 0, 0, 0, time.UTC)
	if preHours {
		start = time.Date(0, 1, 1, 10, 59, 0, 0, time.UTC)
	}
	if afterHours {
		end = time.Date(0, 1, 1, 23, 59, 59, 999999999, time.UTC)
	}

	go func() {
		for {
			now := time.Now().UTC()
			inHours := (start.Hour() <= now.Hour() && now.Hour() <= end.Hour()) && (now.Weekday() >= time.Monday && now.Weekday() <= time.Friday)
			if inHours && !s.active {
				if len(s.subscriptions) == 0 && s.client.Verbose {
					fmt.Println("[Schwabdev] No subscriptions, starting stream anyway.")
				}
				if err := s.Start(receiver); err != nil {
					fmt.Printf("[Schwabdev] Failed to start stream: %v\n", err)
				}
			} else if !inHours && s.active {
				if s.client.Verbose {
					fmt.Println("[Schwabdev] Stopping Stream.")
				}
				if err := s.Stop(); err != nil {
					fmt.Printf("[Schwabdev] Failed to stop stream: %v\n", err)
				}
			}
			time.Sleep(30 * time.Second)
		}
	}()

	if !(start.Hour() <= time.Now().UTC().Hour() && time.Now().UTC().Hour() <= end.Hour()) {
		fmt.Println("[Schwabdev] Stream was started outside of active hours and will launch when in hours.")
	}
}
