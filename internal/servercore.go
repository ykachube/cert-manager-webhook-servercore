package internal

import "time"

type Config struct {
	// Authentication fields
	Username    string
	Password    string
	AccountID   string
	ProjectName string
	AuthURL     string

	// API fields
	ApiUrl   string
	ZoneName string

	AuthToken   string
	TokenExpiry time.Time
}

type RecordResponse struct {
	Records []Record `json:"records"`
	Meta    Meta     `json:"meta"`
}

type ZoneResponse struct {
	Count      int    `json:"count"`
	NextOffset int    `json:"next_offset"`
	Result     []Zone `json:"result"`
}

type Zone struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	ProjectId string `json:"project_id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Comment   string `json:"comment"`
	Disabled  bool   `json:"disabled"`
	Protected bool   `json:"protected"`
}

type Meta struct {
	Pagination Pagination `json:"pagination"`
}

type Pagination struct {
	Page         int `json:"page"`
	PerPage      int `json:"per_page"`
	LastPage     int `json:"last_page"`
	TotalEntries int `json:"total_entries"`
}

type Record struct {
	Type     string `json:"type"`
	Id       string `json:"id"`
	Created  string `json:"created"`
	Modified string `json:"modified"`
	ZoneId   string `json:"zone_id"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Ttl      int    `json:"ttl"`
}

type Verification struct {
	Name  string `json:"name"`
	Token string `json:"token"`
}
