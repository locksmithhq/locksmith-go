package locksmith

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func (l *locksmith) generateAccessToken(ctx context.Context, input AccessTokenInput) (AccessTokenOutput, error) {
	input.ClientID = l.clientID
	input.ClientSecret = l.clientSecret
	input.GrantType = "authorization_code"

	jsonInput, err := json.Marshal(input)
	if err != nil {
		return AccessTokenOutput{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.baseUrl+"/api/oauth2/access-token", bytes.NewReader(jsonInput))
	if err != nil {
		return AccessTokenOutput{}, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return AccessTokenOutput{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResponse ApiError
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return AccessTokenOutput{}, err
		}
		return AccessTokenOutput{}, errorResponse
	}

	var output AccessTokenOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return AccessTokenOutput{}, err
	}
	return output, nil
}

func (l *locksmith) generateRefreshToken(ctx context.Context, input RefreshAccessTokenInput) (AccessTokenOutput, error) {
	input.GrantType = "refresh_token"

	jsonInput, err := json.Marshal(input)
	if err != nil {
		return AccessTokenOutput{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.baseUrl+"/api/oauth2/refresh-token", bytes.NewReader(jsonInput))
	if err != nil {
		return AccessTokenOutput{}, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return AccessTokenOutput{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResponse ApiError
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return AccessTokenOutput{}, err
		}
		return AccessTokenOutput{}, errorResponse
	}

	var output AccessTokenOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return AccessTokenOutput{}, err
	}
	return output, nil
}

func (l *locksmith) createAccount(ctx context.Context, input AccountInput) (AccountOutput, error) {
	jsonInput, err := json.Marshal(input)
	if err != nil {
		return AccountOutput{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.baseUrl+"/api/accounts", bytes.NewReader(jsonInput))
	if err != nil {
		return AccountOutput{}, err
	}

	req.SetBasicAuth(l.clientID, l.clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return AccountOutput{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return AccountOutput{}, errors.New(string(body))
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		var errorResponse ApiError
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return AccountOutput{}, err
		}
		return AccountOutput{}, errorResponse
	}

	var output AccountOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return AccountOutput{}, err
	}
	return output, nil
}

func (l *locksmith) updateAccount(ctx context.Context, input AccountInput) (AccountOutput, error) {
	jsonInput, err := json.Marshal(input)
	if err != nil {
		return AccountOutput{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, l.baseUrl+"/api/accounts/"+input.Id, bytes.NewReader(jsonInput))
	if err != nil {
		return AccountOutput{}, err
	}

	req.SetBasicAuth(l.clientID, l.clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return AccountOutput{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		return AccountOutput{}, errors.New(string(body))
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		var errorResponse ApiError
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return AccountOutput{}, err
		}
		return AccountOutput{}, errorResponse
	}

	var output AccountOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return AccountOutput{}, err
	}
	return output, nil
}

func (l *locksmith) getAccountByID(ctx context.Context, id string) (AccountOutput, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.baseUrl+"/api/accounts/"+id, nil)
	if err != nil {
		return AccountOutput{}, err
	}
	req.SetBasicAuth(l.clientID, l.clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return AccountOutput{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResponse ApiError
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return AccountOutput{}, err
		}
		return AccountOutput{}, errorResponse
	}

	var output AccountOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return AccountOutput{}, err
	}
	return output, nil
}

func (l *locksmith) getPermissionsForUserInDomain(ctx context.Context, sub string, dom string) (PermissionsOutput, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.baseUrl+"/api/acl/permissions/user/"+sub+"/domain/"+dom, nil)
	if err != nil {
		return PermissionsOutput{}, err
	}
	req.SetBasicAuth(l.clientID, l.clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return PermissionsOutput{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResponse ApiError
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return PermissionsOutput{}, err
		}
		return PermissionsOutput{}, errorResponse
	}

	var output PermissionsOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return PermissionsOutput{}, err
	}
	return output, nil
}

func (l *locksmith) enforce(ctx context.Context, sub string, dom string, obj string, act string) (bool, error) {
	if !l.httpEnforce {
		return Enforce(sub, dom, obj, act)
	}

	type enforceInput struct {
		Sub string `json:"sub"`
		Dom string `json:"dom"`
		Obj string `json:"obj"`
		Act string `json:"act"`
		Key string `json:"key"`
	}

	jwtToken := ctx.Value(jwtContextKey)
	if jwtToken == nil {
		return false, errors.New("jwt token not found")
	}

	jsonInput, err := json.Marshal(enforceInput{
		Sub: sub,
		Dom: dom,
		Obj: obj,
		Act: act,
		Key: l.clientSecret,
	})
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.baseUrl+"/api/acl/enforce", bytes.NewReader(jsonInput))
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwtToken.(string))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errorResponse ApiError
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return false, err
		}
		return false, errorResponse
	}

	return true, nil
}
