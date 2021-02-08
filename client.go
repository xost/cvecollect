package main

type Client struct {
}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) Read([]byte) (int, error) {
	return 0, nil
}
