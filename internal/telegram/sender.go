package telegram

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type SenderTelegram struct {
	token  string
	chatID string
}

func NewSenderTelegram(token, chatID string) *SenderTelegram {
	return &SenderTelegram{token: token, chatID: chatID}
}

func (s *SenderTelegram) Send(text string) error {
	body := map[string]any{
		"chat_id": s.chatID,
		"text":    text,
		"parse_mode": "Markdown",
	}

	b, _ := json.Marshal(body)

	resp, err := http.Post(
		fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", s.token),
		"application/json",
		bytes.NewReader(b),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram http %d", resp.StatusCode)
	}
	return nil
}
