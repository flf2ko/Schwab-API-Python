package schwabdev

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client 结构体用于访问Schwab API
type Client struct {
	AppKey              string
	AppSecret           string
	CallbackURL         string
	TokensFile          string
	Timeout             time.Duration
	Verbose             bool
	UpdateTokensAuto    bool
	AccessToken         string
	RefreshToken        string
	IDToken             string
	accessTokenIssued   time.Time
	refreshTokenIssued  time.Time
	accessTokenTimeout  time.Duration
	refreshTokenTimeout time.Duration
	stream              *Stream
}

// NewClient 创建一个新的Client实例
func NewClient(appKey, appSecret, callbackURL, tokensFile string, timeout time.Duration, verbose, updateTokensAuto bool) (*Client, error) {
	if appKey == "" {
		return nil, fmt.Errorf("appKey cannot be empty")
	}
	if appSecret == "" {
		return nil, fmt.Errorf("appSecret cannot be empty")
	}
	if callbackURL == "" {
		return nil, fmt.Errorf("callbackURL cannot be empty")
	}
	if tokensFile == "" {
		return nil, fmt.Errorf("tokensFile cannot be empty")
	}
	if len(appKey) != 32 || len(appSecret) != 16 {
		return nil, fmt.Errorf("invalid app key or app secret length")
	}
	if !strings.HasPrefix(callbackURL, "https") {
		return nil, fmt.Errorf("callbackURL must be https")
	}
	if strings.HasSuffix(callbackURL, "/") {
		return nil, fmt.Errorf("callbackURL cannot end with '/'")
	}
	if strings.HasSuffix(tokensFile, "/") {
		return nil, fmt.Errorf("tokensFile cannot be a directory")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("timeout must be greater than 0")
	}

	client := &Client{
		AppKey:              appKey,
		AppSecret:           appSecret,
		CallbackURL:         callbackURL,
		TokensFile:          tokensFile,
		Timeout:             timeout,
		Verbose:             verbose,
		UpdateTokensAuto:    updateTokensAuto,
		accessTokenTimeout:  1800 * time.Second,
		refreshTokenTimeout: 7 * 24 * 60 * 60 * time.Second,
	}

	client.stream = NewStream(client)

	// 尝试从文件加载令牌
	if err := client.loadTokens(); err != nil {
		if os.IsNotExist(err) {
			// 如果文件不存在，创建一个新文件
			if client.Verbose {
				fmt.Printf("[Schwabdev] Token file does not exist, creating \"%s\"\n", tokensFile)
			}
			if err := os.WriteFile(tokensFile, []byte("{}"), 0644); err != nil {
				return nil, fmt.Errorf("failed to create token file: %v", err)
			}
			// 更新令牌
			if err := client.updateRefreshToken(); err != nil {
				return nil, fmt.Errorf("failed to update refresh token: %v", err)
			}
		} else {
			return nil, fmt.Errorf("failed to load tokens: %v", err)
		}
	}

	// 如果需要自动更新令牌，启动一个goroutine来检查和更新
	if updateTokensAuto {
		go client.tokenChecker()
	} else if client.Verbose {
		fmt.Println("[Schwabdev] Warning: Tokens will not be updated automatically.")
	}

	if client.Verbose {
		fmt.Println("[Schwabdev] Client Initialization Complete")
	}

	return client, nil
}

// loadTokens 从文件加载令牌
func (c *Client) loadTokens() error {
	data, err := os.ReadFile(c.TokensFile)
	if err != nil {
		return err
	}

	var tokenData struct {
		AccessTokenIssued  string `json:"access_token_issued"`
		RefreshTokenIssued string `json:"refresh_token_issued"`
		TokenDictionary    struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			IDToken      string `json:"id_token"`
		} `json:"token_dictionary"`
	}

	if err := json.Unmarshal(data, &tokenData); err != nil {
		return err
	}

	c.AccessToken = tokenData.TokenDictionary.AccessToken
	c.RefreshToken = tokenData.TokenDictionary.RefreshToken
	c.IDToken = tokenData.TokenDictionary.IDToken

	c.accessTokenIssued, _ = time.Parse(time.RFC3339, tokenData.AccessTokenIssued)
	c.refreshTokenIssued, _ = time.Parse(time.RFC3339, tokenData.RefreshTokenIssued)

	return nil
}

// saveTokens 保存令牌到文件
func (c *Client) saveTokens() error {
	tokenData := struct {
		AccessTokenIssued  string `json:"access_token_issued"`
		RefreshTokenIssued string `json:"refresh_token_issued"`
		TokenDictionary    struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			IDToken      string `json:"id_token"`
		} `json:"token_dictionary"`
	}{
		AccessTokenIssued:  c.accessTokenIssued.Format(time.RFC3339),
		RefreshTokenIssued: c.refreshTokenIssued.Format(time.RFC3339),
		TokenDictionary: struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			IDToken      string `json:"id_token"`
		}{
			AccessToken:  c.AccessToken,
			RefreshToken: c.RefreshToken,
			IDToken:      c.IDToken,
		},
	}

	data, err := json.MarshalIndent(tokenData, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(c.TokensFile, data, 0644)
}

// updateTokens 检查并更新令牌
func (c *Client) updateTokens(force bool) error {
	rtDelta := c.refreshTokenTimeout - time.Since(c.refreshTokenIssued)
	if rtDelta < 12*time.Hour {
		fmt.Printf("[Schwabdev] The refresh token will expire soon! (%s remaining)\n", rtDelta.Round(time.Second))
	}

	if rtDelta < time.Hour || force {
		fmt.Println("[Schwabdev] The refresh token has expired!")
		return c.updateRefreshToken()
	} else if time.Since(c.accessTokenIssued) > c.accessTokenTimeout-time.Minute {
		if c.Verbose {
			fmt.Println("[Schwabdev] The access token has expired, updating automatically.")
		}
		return c.updateAccessToken()
	}

	return nil
}

// tokenChecker 定期检查并更新令牌
func (c *Client) tokenChecker() {
	for {
		if err := c.updateTokens(false); err != nil {
			fmt.Printf("[Schwabdev] Failed to update tokens: %v\n", err)
		}
		time.Sleep(30 * time.Second)
	}
}

// updateAccessToken 更新访问令牌
func (c *Client) updateAccessToken() error {
	response, err := c.postOAuthToken("refresh_token", c.RefreshToken)
	if err != nil {
		return err
	}

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}

	if err := json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
		return err
	}

	c.AccessToken = tokenResponse.AccessToken
	c.RefreshToken = tokenResponse.RefreshToken
	c.IDToken = tokenResponse.IDToken
	c.accessTokenIssued = time.Now()

	if err := c.saveTokens(); err != nil {
		return err
	}

	if c.Verbose {
		fmt.Printf("[Schwabdev] Access token updated: %s\n", c.accessTokenIssued)
	}

	return nil
}

// updateRefreshToken 更新刷新令牌
func (c *Client) updateRefreshToken() error {
	authURL := fmt.Sprintf("https://api.schwabapi.com/v1/oauth/authorize?client_id=%s&redirect_uri=%s", c.AppKey, c.CallbackURL)
	fmt.Printf("[Schwabdev] Open to authenticate: %s\n", authURL)
	fmt.Print("After authorizing, paste the address bar url here: ")

	var responseURL string
	fmt.Scanln(&responseURL)

	codeStart := strings.Index(responseURL, "code=")
	codeEnd := strings.Index(responseURL, "%40")
	if codeStart == -1 || codeEnd == -1 {
		return fmt.Errorf("invalid response URL")
	}

	code := responseURL[codeStart+5:codeEnd] + "@"

	response, err := c.postOAuthToken("authorization_code", code)
	if err != nil {
		return err
	}

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}

	if err := json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
		return err
	}

	c.AccessToken = tokenResponse.AccessToken
	c.RefreshToken = tokenResponse.RefreshToken
	c.IDToken = tokenResponse.IDToken
	c.accessTokenIssued = time.Now()
	c.refreshTokenIssued = time.Now()

	if err := c.saveTokens(); err != nil {
		return err
	}

	if c.Verbose {
		fmt.Println("[Schwabdev] Refresh and Access tokens updated")
	}

	return nil
}

// postOAuthToken 发送OAuth令牌请求
func (c *Client) postOAuthToken(grantType, code string) (*http.Response, error) {
	data := url.Values{}
	data.Set("grant_type", grantType)

	if grantType == "authorization_code" {
		data.Set("code", code)
		data.Set("redirect_uri", c.CallbackURL)
	} else if grantType == "refresh_token" {
		data.Set("refresh_token", code)
	} else {
		return nil, fmt.Errorf("invalid grant type")
	}

	req, err := http.NewRequest("POST", "https://api.schwabapi.com/v1/oauth/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.AppKey+":"+c.AppSecret)))

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// AccountLinked 获取所有链接的账户号码
func (c *Client) AccountLinked() (*http.Response, error) {
	req, err := http.NewRequest("GET", "https://api.schwabapi.com/trader/v1/accounts/accountNumbers", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// AccountDetailsAll 获取所有链接账户的详细信息
func (c *Client) AccountDetailsAll(fields string) (*http.Response, error) {
	req, err := http.NewRequest("GET", "https://api.schwabapi.com/trader/v1/accounts/", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	q := req.URL.Query()
	if fields != "" {
		q.Add("fields", fields)
	}
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// AccountDetails 获取特定账户的详细信息
func (c *Client) AccountDetails(accountHash, fields string) (*http.Response, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.schwabapi.com/trader/v1/accounts/%s", accountHash), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	q := req.URL.Query()
	if fields != "" {
		q.Add("fields", fields)
	}
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// AccountOrders 获取特定账户的订单
func (c *Client) AccountOrders(accountHash string, fromEnteredTime, toEnteredTime time.Time, maxResults int, status string) (*http.Response, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.schwabapi.com/trader/v1/accounts/%s/orders", accountHash), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	req.Header.Set("Accept", "application/json")

	q := req.URL.Query()
	q.Add("fromEnteredTime", fromEnteredTime.Format(time.RFC3339))
	q.Add("toEnteredTime", toEnteredTime.Format(time.RFC3339))
	if maxResults > 0 {
		q.Add("maxResults", fmt.Sprintf("%d", maxResults))
	}
	if status != "" {
		q.Add("status", status)
	}
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// OrderPlace 下单
func (c *Client) OrderPlace(accountHash string, order map[string]interface{}) (*http.Response, error) {
	orderJSON, err := json.Marshal(order)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("https://api.schwabapi.com/trader/v1/accounts/%s/orders", accountHash), bytes.NewBuffer(orderJSON))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// OrderDetails 获取特定订单的详情
func (c *Client) OrderDetails(accountHash string, orderID string) (*http.Response, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.schwabapi.com/trader/v1/accounts/%s/orders/%s", accountHash, orderID), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// OrderCancel 取消订单
func (c *Client) OrderCancel(accountHash string, orderID string) (*http.Response, error) {
	req, err := http.NewRequest("DELETE", fmt.Sprintf("https://api.schwabapi.com/trader/v1/accounts/%s/orders/%s", accountHash, orderID), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// OrderReplace 替换订单
func (c *Client) OrderReplace(accountHash string, orderID string, order map[string]interface{}) (*http.Response, error) {
	orderJSON, err := json.Marshal(order)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PUT", fmt.Sprintf("https://api.schwabapi.com/trader/v1/accounts/%s/orders/%s", accountHash, orderID), bytes.NewBuffer(orderJSON))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// AccountOrdersAll 获取所有账户的订单
func (c *Client) AccountOrdersAll(fromEnteredTime, toEnteredTime time.Time, maxResults int, status string) (*http.Response, error) {
	req, err := http.NewRequest("GET", "https://api.schwabapi.com/trader/v1/orders", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	req.Header.Set("Accept", "application/json")

	q := req.URL.Query()
	q.Add("fromEnteredTime", fromEnteredTime.Format(time.RFC3339))
	q.Add("toEnteredTime", toEnteredTime.Format(time.RFC3339))
	if maxResults > 0 {
		q.Add("maxResults", fmt.Sprintf("%d", maxResults))
	}
	if status != "" {
		q.Add("status", status)
	}
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// Transactions 获取特定账户的交易
func (c *Client) Transactions(accountHash string, startDate, endDate time.Time, types string, symbol string) (*http.Response, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.schwabapi.com/trader/v1/accounts/%s/transactions", accountHash), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	q := req.URL.Query()
	q.Add("startDate", startDate.Format("2006-01-02"))
	q.Add("endDate", endDate.Format("2006-01-02"))
	q.Add("types", types)
	if symbol != "" {
		q.Add("symbol", symbol)
	}
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// TransactionDetails 获取特定交易的详情
func (c *Client) TransactionDetails(accountHash string, transactionID string) (*http.Response, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.schwabapi.com/trader/v1/accounts/%s/transactions/%s", accountHash, transactionID), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// Preferences 获取用户偏好信息
func (c *Client) Preferences() (*http.Response, error) {
	req, err := http.NewRequest("GET", "https://api.schwabapi.com/trader/v1/userPreference", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// Quotes 获取多个股票的报价
func (c *Client) Quotes(symbols []string, fields string, indicative bool) (*http.Response, error) {
	req, err := http.NewRequest("GET", "https://api.schwabapi.com/marketdata/v1/quotes", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	q := req.URL.Query()
	q.Add("symbols", strings.Join(symbols, ","))
	if fields != "" {
		q.Add("fields", fields)
	}
	q.Add("indicative", fmt.Sprintf("%t", indicative))
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// Quote 获取单个股票的报价
func (c *Client) Quote(symbolID string, fields string) (*http.Response, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.schwabapi.com/marketdata/v1/%s/quotes", url.PathEscape(symbolID)), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	q := req.URL.Query()
	if fields != "" {
		q.Add("fields", fields)
	}
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// OptionChains 获取期权链信息
func (c *Client) OptionChains(symbol string, contractType string, strikeCount int, includeUnderlyingQuote bool, strategy string,
	interval float64, strike float64, rangeValue string, fromDate, toDate time.Time, volatility float64, underlyingPrice float64,
	interestRate float64, daysToExpiration int, expMonth string, optionType string, entitlement string) (*http.Response, error) {

	req, err := http.NewRequest("GET", "https://api.schwabapi.com/marketdata/v1/chains", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	q := req.URL.Query()
	q.Add("symbol", symbol)
	if contractType != "" {
		q.Add("contractType", contractType)
	}
	if strikeCount > 0 {
		q.Add("strikeCount", fmt.Sprintf("%d", strikeCount))
	}
	q.Add("includeUnderlyingQuote", fmt.Sprintf("%t", includeUnderlyingQuote))
	if strategy != "" {
		q.Add("strategy", strategy)
	}
	if interval > 0 {
		q.Add("interval", fmt.Sprintf("%f", interval))
	}
	if strike > 0 {
		q.Add("strike", fmt.Sprintf("%f", strike))
	}
	if rangeValue != "" {
		q.Add("range", rangeValue)
	}
	if !fromDate.IsZero() {
		q.Add("fromDate", fromDate.Format("2006-01-02"))
	}
	if !toDate.IsZero() {
		q.Add("toDate", toDate.Format("2006-01-02"))
	}
	if volatility > 0 {
		q.Add("volatility", fmt.Sprintf("%f", volatility))
	}
	if underlyingPrice > 0 {
		q.Add("underlyingPrice", fmt.Sprintf("%f", underlyingPrice))
	}
	if interestRate > 0 {
		q.Add("interestRate", fmt.Sprintf("%f", interestRate))
	}
	if daysToExpiration > 0 {
		q.Add("daysToExpiration", fmt.Sprintf("%d", daysToExpiration))
	}
	if expMonth != "" {
		q.Add("expMonth", expMonth)
	}
	if optionType != "" {
		q.Add("optionType", optionType)
	}
	if entitlement != "" {
		q.Add("entitlement", entitlement)
	}
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// OptionExpirationChain 获取期权到期链信息
func (c *Client) OptionExpirationChain(symbol string) (*http.Response, error) {
	req, err := http.NewRequest("GET", "https://api.schwabapi.com/marketdata/v1/expirationchain", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	q := req.URL.Query()
	q.Add("symbol", symbol)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// PriceHistory 获取价格历史
func (c *Client) PriceHistory(symbol string, periodType string, period int, frequencyType string, frequency int, startDate, endDate time.Time, needExtendedHoursData, needPreviousClose bool) (*http.Response, error) {
	req, err := http.NewRequest("GET", "https://api.schwabapi.com/marketdata/v1/pricehistory", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	q := req.URL.Query()
	q.Add("symbol", symbol)
	if periodType != "" {
		q.Add("periodType", periodType)
	}
	if period > 0 {
		q.Add("period", fmt.Sprintf("%d", period))
	}
	if frequencyType != "" {
		q.Add("frequencyType", frequencyType)
	}
	if frequency > 0 {
		q.Add("frequency", fmt.Sprintf("%d", frequency))
	}
	if !startDate.IsZero() {
		q.Add("startDate", fmt.Sprintf("%d", startDate.UnixNano()/int64(time.Millisecond)))
	}
	if !endDate.IsZero() {
		q.Add("endDate", fmt.Sprintf("%d", endDate.UnixNano()/int64(time.Millisecond)))
	}
	q.Add("needExtendedHoursData", fmt.Sprintf("%t", needExtendedHoursData))
	q.Add("needPreviousClose", fmt.Sprintf("%t", needPreviousClose))
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// Movers 获取市场涨跌幅
func (c *Client) Movers(symbol string, sort string, frequency int) (*http.Response, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.schwabapi.com/marketdata/v1/movers/%s", symbol), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	req.Header.Set("Accept", "application/json")

	q := req.URL.Query()
	if sort != "" {
		q.Add("sort", sort)
	}
	if frequency > 0 {
		q.Add("frequency", fmt.Sprintf("%d", frequency))
	}
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// MarketHours 获取市场交易时间
func (c *Client) MarketHours(symbols []string, date time.Time) (*http.Response, error) {
	req, err := http.NewRequest("GET", "https://api.schwabapi.com/marketdata/v1/markets", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	q := req.URL.Query()
	q.Add("markets", strings.Join(symbols, ","))
	if !date.IsZero() {
		q.Add("date", date.Format("2006-01-02"))
	}
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// MarketHour 获取单个市场的交易时间
func (c *Client) MarketHour(marketID string, date time.Time) (*http.Response, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.schwabapi.com/marketdata/v1/markets/%s", marketID), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	q := req.URL.Query()
	if !date.IsZero() {
		q.Add("date", date.Format("2006-01-02"))
	}
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// Instruments 获取金融工具信息
func (c *Client) Instruments(symbol, projection string) (*http.Response, error) {
	req, err := http.NewRequest("GET", "https://api.schwabapi.com/marketdata/v1/instruments", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	q := req.URL.Query()
	q.Add("symbol", symbol)
	q.Add("projection", projection)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}

// InstrumentCUSIP 获取特定CUSIP的金融工具信息
func (c *Client) InstrumentCUSIP(cusipID string) (*http.Response, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.schwabapi.com/marketdata/v1/instruments/%s", cusipID), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.AccessToken)

	client := &http.Client{Timeout: c.Timeout}
	return client.Do(req)
}
