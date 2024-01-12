package infra

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func Contains(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func SendGetRequest(url, token string) ([]byte, error) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}
	if token != "" {
		req.Header.Set("token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error Sending equest: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %v", resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	return body, nil
}
