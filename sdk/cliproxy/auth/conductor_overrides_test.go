package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

func TestManager_ShouldRetryAfterError_RespectsAuthRequestRetryOverride(t *testing.T) {
	m := NewManager(nil, nil, nil)
	m.SetRetryConfig(3, 30*time.Second, 0)

	model := "test-model"
	next := time.Now().Add(5 * time.Second)

	auth := &Auth{
		ID:       "auth-1",
		Provider: "claude",
		Metadata: map[string]any{
			"request_retry": float64(0),
		},
		ModelStates: map[string]*ModelState{
			model: {
				Unavailable:    true,
				Status:         StatusError,
				NextRetryAfter: next,
			},
		},
	}
	if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	_, _, maxWait := m.retrySettings()
	wait, shouldRetry := m.shouldRetryAfterError(&Error{HTTPStatus: 500, Message: "boom"}, 0, []string{"claude"}, model, maxWait)
	if shouldRetry {
		t.Fatalf("expected shouldRetry=false for request_retry=0, got true (wait=%v)", wait)
	}

	auth.Metadata["request_retry"] = float64(1)
	if _, errUpdate := m.Update(context.Background(), auth); errUpdate != nil {
		t.Fatalf("update auth: %v", errUpdate)
	}

	wait, shouldRetry = m.shouldRetryAfterError(&Error{HTTPStatus: 500, Message: "boom"}, 0, []string{"claude"}, model, maxWait)
	if !shouldRetry {
		t.Fatalf("expected shouldRetry=true for request_retry=1, got false")
	}
	if wait <= 0 {
		t.Fatalf("expected wait > 0, got %v", wait)
	}

	_, shouldRetry = m.shouldRetryAfterError(&Error{HTTPStatus: 500, Message: "boom"}, 1, []string{"claude"}, model, maxWait)
	if shouldRetry {
		t.Fatalf("expected shouldRetry=false on attempt=1 for request_retry=1, got true")
	}
}

type credentialRetryLimitExecutor struct {
	id string

	mu    sync.Mutex
	calls int
}

func (e *credentialRetryLimitExecutor) Identifier() string {
	return e.id
}

func (e *credentialRetryLimitExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.recordCall()
	return cliproxyexecutor.Response{}, &Error{HTTPStatus: 500, Message: "boom"}
}

func (e *credentialRetryLimitExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.recordCall()
	return nil, &Error{HTTPStatus: 500, Message: "boom"}
}

func (e *credentialRetryLimitExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e *credentialRetryLimitExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.recordCall()
	return cliproxyexecutor.Response{}, &Error{HTTPStatus: 500, Message: "boom"}
}

func (e *credentialRetryLimitExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *credentialRetryLimitExecutor) recordCall() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
}

func (e *credentialRetryLimitExecutor) Calls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

type authFallbackExecutor struct {
	id string

	mu                sync.Mutex
	executeCalls      []string
	countCalls        []string
	streamCalls       []string
	executeErrors     map[string]error
	countErrors       map[string]error
	streamFirstErrors map[string]error
}

func (e *authFallbackExecutor) Identifier() string {
	return e.id
}

func (e *authFallbackExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.mu.Lock()
	e.executeCalls = append(e.executeCalls, auth.ID)
	err := e.executeErrors[auth.ID]
	e.mu.Unlock()
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	return cliproxyexecutor.Response{Payload: []byte(auth.ID)}, nil
}

func (e *authFallbackExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.mu.Lock()
	e.streamCalls = append(e.streamCalls, auth.ID)
	err := e.streamFirstErrors[auth.ID]
	e.mu.Unlock()

	ch := make(chan cliproxyexecutor.StreamChunk, 1)
	if err != nil {
		ch <- cliproxyexecutor.StreamChunk{Err: err}
		close(ch)
		return &cliproxyexecutor.StreamResult{Headers: http.Header{"X-Auth": {auth.ID}}, Chunks: ch}, nil
	}
	ch <- cliproxyexecutor.StreamChunk{Payload: []byte(auth.ID)}
	close(ch)
	return &cliproxyexecutor.StreamResult{Headers: http.Header{"X-Auth": {auth.ID}}, Chunks: ch}, nil
}

func (e *authFallbackExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e *authFallbackExecutor) CountTokens(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.mu.Lock()
	e.countCalls = append(e.countCalls, auth.ID)
	err := e.countErrors[auth.ID]
	e.mu.Unlock()
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	return cliproxyexecutor.Response{Payload: []byte(auth.ID)}, nil
}

func (e *authFallbackExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *authFallbackExecutor) ExecuteCalls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.executeCalls))
	copy(out, e.executeCalls)
	return out
}

func (e *authFallbackExecutor) CountCalls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.countCalls))
	copy(out, e.countCalls)
	return out
}

func (e *authFallbackExecutor) StreamCalls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.streamCalls))
	copy(out, e.streamCalls)
	return out
}

func newCredentialRetryLimitTestManager(t *testing.T, maxRetryCredentials int) (*Manager, *credentialRetryLimitExecutor) {
	t.Helper()

	m := NewManager(nil, nil, nil)
	m.SetRetryConfig(0, 0, maxRetryCredentials)

	executor := &credentialRetryLimitExecutor{id: "claude"}
	m.RegisterExecutor(executor)

	baseID := uuid.NewString()
	auth1 := &Auth{ID: baseID + "-auth-1", Provider: "claude"}
	auth2 := &Auth{ID: baseID + "-auth-2", Provider: "claude"}

	// Auth selection requires that the global model registry knows each credential supports the model.
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth1.ID, "claude", []*registry.ModelInfo{{ID: "test-model"}})
	reg.RegisterClient(auth2.ID, "claude", []*registry.ModelInfo{{ID: "test-model"}})
	t.Cleanup(func() {
		reg.UnregisterClient(auth1.ID)
		reg.UnregisterClient(auth2.ID)
	})

	if _, errRegister := m.Register(context.Background(), auth1); errRegister != nil {
		t.Fatalf("register auth1: %v", errRegister)
	}
	if _, errRegister := m.Register(context.Background(), auth2); errRegister != nil {
		t.Fatalf("register auth2: %v", errRegister)
	}

	return m, executor
}

func TestManager_MaxRetryCredentials_LimitsCrossCredentialRetries(t *testing.T) {
	request := cliproxyexecutor.Request{Model: "test-model"}
	testCases := []struct {
		name   string
		invoke func(*Manager) error
	}{
		{
			name: "execute",
			invoke: func(m *Manager) error {
				_, errExecute := m.Execute(context.Background(), []string{"claude"}, request, cliproxyexecutor.Options{})
				return errExecute
			},
		},
		{
			name: "execute_count",
			invoke: func(m *Manager) error {
				_, errExecute := m.ExecuteCount(context.Background(), []string{"claude"}, request, cliproxyexecutor.Options{})
				return errExecute
			},
		},
		{
			name: "execute_stream",
			invoke: func(m *Manager) error {
				_, errExecute := m.ExecuteStream(context.Background(), []string{"claude"}, request, cliproxyexecutor.Options{})
				return errExecute
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			limitedManager, limitedExecutor := newCredentialRetryLimitTestManager(t, 1)
			if errInvoke := tc.invoke(limitedManager); errInvoke == nil {
				t.Fatalf("expected error for limited retry execution")
			}
			if calls := limitedExecutor.Calls(); calls != 1 {
				t.Fatalf("expected 1 call with max-retry-credentials=1, got %d", calls)
			}

			unlimitedManager, unlimitedExecutor := newCredentialRetryLimitTestManager(t, 0)
			if errInvoke := tc.invoke(unlimitedManager); errInvoke == nil {
				t.Fatalf("expected error for unlimited retry execution")
			}
			if calls := unlimitedExecutor.Calls(); calls != 2 {
				t.Fatalf("expected 2 calls with max-retry-credentials=0, got %d", calls)
			}
		})
	}
}

func TestManager_ModelSupportBadRequest_FallsBackAndSuspendsAuth(t *testing.T) {
	m := NewManager(nil, nil, nil)
	executor := &authFallbackExecutor{
		id: "claude",
		executeErrors: map[string]error{
			"aa-bad-auth": &Error{
				HTTPStatus: http.StatusBadRequest,
				Message:    "invalid_request_error: The requested model is not supported.",
			},
		},
	}
	m.RegisterExecutor(executor)

	model := "claude-opus-4-6"
	badAuth := &Auth{ID: "aa-bad-auth", Provider: "claude"}
	goodAuth := &Auth{ID: "bb-good-auth", Provider: "claude"}

	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(badAuth.ID, "claude", []*registry.ModelInfo{{ID: model}})
	reg.RegisterClient(goodAuth.ID, "claude", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() {
		reg.UnregisterClient(badAuth.ID)
		reg.UnregisterClient(goodAuth.ID)
	})

	if _, errRegister := m.Register(context.Background(), badAuth); errRegister != nil {
		t.Fatalf("register bad auth: %v", errRegister)
	}
	if _, errRegister := m.Register(context.Background(), goodAuth); errRegister != nil {
		t.Fatalf("register good auth: %v", errRegister)
	}

	request := cliproxyexecutor.Request{Model: model}
	for i := 0; i < 2; i++ {
		resp, errExecute := m.Execute(context.Background(), []string{"claude"}, request, cliproxyexecutor.Options{})
		if errExecute != nil {
			t.Fatalf("execute %d error = %v, want success", i, errExecute)
		}
		if string(resp.Payload) != goodAuth.ID {
			t.Fatalf("execute %d payload = %q, want %q", i, string(resp.Payload), goodAuth.ID)
		}
	}

	got := executor.ExecuteCalls()
	want := []string{badAuth.ID, goodAuth.ID, goodAuth.ID}
	if len(got) != len(want) {
		t.Fatalf("execute calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("execute call %d auth = %q, want %q", i, got[i], want[i])
		}
	}

	updatedBad, ok := m.GetByID(badAuth.ID)
	if !ok || updatedBad == nil {
		t.Fatalf("expected bad auth to remain registered")
	}
	state := updatedBad.ModelStates[model]
	if state == nil {
		t.Fatalf("expected model state for %q", model)
	}
	if !state.Unavailable {
		t.Fatalf("expected bad auth model state to be unavailable")
	}
	if state.NextRetryAfter.IsZero() {
		t.Fatalf("expected bad auth model state cooldown to be set")
	}
}

func TestManagerExecuteStream_ModelSupportBadRequestFallsBackAndSuspendsAuth(t *testing.T) {
	m := NewManager(nil, nil, nil)
	executor := &authFallbackExecutor{
		id: "claude",
		streamFirstErrors: map[string]error{
			"aa-bad-auth": &Error{
				HTTPStatus: http.StatusBadRequest,
				Message:    "invalid_request_error: The requested model is not supported.",
			},
		},
	}
	m.RegisterExecutor(executor)

	model := "claude-opus-4-6"
	badAuth := &Auth{ID: "aa-bad-auth", Provider: "claude"}
	goodAuth := &Auth{ID: "bb-good-auth", Provider: "claude"}

	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(badAuth.ID, "claude", []*registry.ModelInfo{{ID: model}})
	reg.RegisterClient(goodAuth.ID, "claude", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() {
		reg.UnregisterClient(badAuth.ID)
		reg.UnregisterClient(goodAuth.ID)
	})

	if _, errRegister := m.Register(context.Background(), badAuth); errRegister != nil {
		t.Fatalf("register bad auth: %v", errRegister)
	}
	if _, errRegister := m.Register(context.Background(), goodAuth); errRegister != nil {
		t.Fatalf("register good auth: %v", errRegister)
	}

	request := cliproxyexecutor.Request{Model: model}
	for i := 0; i < 2; i++ {
		streamResult, errExecute := m.ExecuteStream(context.Background(), []string{"claude"}, request, cliproxyexecutor.Options{})
		if errExecute != nil {
			t.Fatalf("execute stream %d error = %v, want success", i, errExecute)
		}
		var payload []byte
		for chunk := range streamResult.Chunks {
			if chunk.Err != nil {
				t.Fatalf("execute stream %d chunk error = %v, want success", i, chunk.Err)
			}
			payload = append(payload, chunk.Payload...)
		}
		if string(payload) != goodAuth.ID {
			t.Fatalf("execute stream %d payload = %q, want %q", i, string(payload), goodAuth.ID)
		}
	}

	got := executor.StreamCalls()
	want := []string{badAuth.ID, goodAuth.ID, goodAuth.ID}
	if len(got) != len(want) {
		t.Fatalf("stream calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stream call %d auth = %q, want %q", i, got[i], want[i])
		}
	}

	updatedBad, ok := m.GetByID(badAuth.ID)
	if !ok || updatedBad == nil {
		t.Fatalf("expected bad auth to remain registered")
	}
	state := updatedBad.ModelStates[model]
	if state == nil {
		t.Fatalf("expected model state for %q", model)
	}
	if !state.Unavailable {
		t.Fatalf("expected bad auth model state to be unavailable")
	}
	if state.NextRetryAfter.IsZero() {
		t.Fatalf("expected bad auth model state cooldown to be set")
	}
}

func TestManager_FatalAuthFailure_RemovesAuthAndFallsBackAcrossExecutionModes(t *testing.T) {
	testCases := []struct {
		name  string
		invoke func(*Manager, cliproxyexecutor.Request) (string, error)
		calls func(*authFallbackExecutor) []string
	}{
		{
			name: "execute",
			invoke: func(m *Manager, request cliproxyexecutor.Request) (string, error) {
				resp, err := m.Execute(context.Background(), []string{"claude"}, request, cliproxyexecutor.Options{})
				return string(resp.Payload), err
			},
			calls: func(executor *authFallbackExecutor) []string { return executor.ExecuteCalls() },
		},
		{
			name: "execute_count",
			invoke: func(m *Manager, request cliproxyexecutor.Request) (string, error) {
				resp, err := m.ExecuteCount(context.Background(), []string{"claude"}, request, cliproxyexecutor.Options{})
				return string(resp.Payload), err
			},
			calls: func(executor *authFallbackExecutor) []string { return executor.CountCalls() },
		},
		{
			name: "execute_stream",
			invoke: func(m *Manager, request cliproxyexecutor.Request) (string, error) {
				streamResult, err := m.ExecuteStream(context.Background(), []string{"claude"}, request, cliproxyexecutor.Options{})
				if err != nil {
					return "", err
				}
				var payload []byte
				for chunk := range streamResult.Chunks {
					if chunk.Err != nil {
						return "", chunk.Err
					}
					payload = append(payload, chunk.Payload...)
				}
				return string(payload), nil
			},
			calls: func(executor *authFallbackExecutor) []string { return executor.StreamCalls() },
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(nil, nil, nil)
			executor := &authFallbackExecutor{
				id: "claude",
				executeErrors: map[string]error{
					"aa-bad-auth": &Error{HTTPStatus: http.StatusUnauthorized, Message: "invalid api key"},
				},
				countErrors: map[string]error{
					"aa-bad-auth": &Error{HTTPStatus: http.StatusUnauthorized, Message: "invalid api key"},
				},
				streamFirstErrors: map[string]error{
					"aa-bad-auth": &Error{HTTPStatus: http.StatusUnauthorized, Message: "invalid api key"},
				},
			}
			m.RegisterExecutor(executor)

			model := "claude-opus-4-6"
			badAuth := &Auth{ID: "aa-bad-auth", Provider: "claude"}
			goodAuth := &Auth{ID: "bb-good-auth", Provider: "claude"}
			registerSchedulerModels(t, "claude", model, badAuth.ID, goodAuth.ID)

			if _, err := m.Register(context.Background(), badAuth); err != nil {
				t.Fatalf("register bad auth: %v", err)
			}
			if _, err := m.Register(context.Background(), goodAuth); err != nil {
				t.Fatalf("register good auth: %v", err)
			}

			request := cliproxyexecutor.Request{Model: model}
			payload, err := tc.invoke(m, request)
			if err != nil {
				t.Fatalf("first invoke error = %v, want success", err)
			}
			if payload != goodAuth.ID {
				t.Fatalf("first invoke payload = %q, want %q", payload, goodAuth.ID)
			}

			if _, ok := m.GetByID(badAuth.ID); ok {
				t.Fatalf("expected bad auth to be removed")
			}
			if models := registry.GetGlobalRegistry().GetModelsForClient(badAuth.ID); len(models) != 0 {
				t.Fatalf("expected bad auth to be unregistered from model registry, got %d models", len(models))
			}

			payload, err = tc.invoke(m, request)
			if err != nil {
				t.Fatalf("second invoke error = %v, want success", err)
			}
			if payload != goodAuth.ID {
				t.Fatalf("second invoke payload = %q, want %q", payload, goodAuth.ID)
			}

			got := tc.calls(executor)
			want := []string{badAuth.ID, goodAuth.ID, goodAuth.ID}
			if len(got) != len(want) {
				t.Fatalf("calls = %v, want %v", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("call %d auth = %q, want %q", i, got[i], want[i])
				}
			}
		})
	}
}

func TestManager_FatalAuthFailure_DeletesPersistedAuthRecord(t *testing.T) {
	store := &countingStore{}
	m := NewManager(store, nil, nil)
	executor := &authFallbackExecutor{
		id: "claude",
		executeErrors: map[string]error{
			"aa-bad-auth.json": &Error{HTTPStatus: http.StatusUnauthorized, Message: "invalid api key"},
		},
	}
	m.RegisterExecutor(executor)

	model := "claude-opus-4-6"
	badAuth := &Auth{
		ID:       "aa-bad-auth.json",
		Provider: "claude",
		Metadata: map[string]any{"email": "bad@example.com"},
	}
	goodAuth := &Auth{ID: "bb-good-auth", Provider: "claude"}
	registerSchedulerModels(t, "claude", model, badAuth.ID, goodAuth.ID)

	if _, err := m.Register(context.Background(), badAuth); err != nil {
		t.Fatalf("register bad auth: %v", err)
	}
	if _, err := m.Register(context.Background(), goodAuth); err != nil {
		t.Fatalf("register good auth: %v", err)
	}

	resp, err := m.Execute(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("execute error = %v, want success", err)
	}
	if string(resp.Payload) != goodAuth.ID {
		t.Fatalf("execute payload = %q, want %q", string(resp.Payload), goodAuth.ID)
	}
	if got := store.deleteCount.Load(); got != 1 {
		t.Fatalf("expected 1 Delete call, got %d", got)
	}
	deletedIDs := store.DeletedIDs()
	if len(deletedIDs) != 1 || deletedIDs[0] != badAuth.ID {
		t.Fatalf("deleted IDs = %v, want [%s]", deletedIDs, badAuth.ID)
	}
}

func TestManager_GeminiVirtualChildFatalFailure_RemovesWholeVirtualGroup(t *testing.T) {
	m := NewManager(nil, nil, nil)
	executor := &authFallbackExecutor{
		id: "gemini-cli",
		executeErrors: map[string]error{
			"cred-a.json::proj-a1": &Error{HTTPStatus: http.StatusUnauthorized, Message: "access token expired"},
		},
	}
	m.RegisterExecutor(executor)

	model := "gemini-2.5-pro"
	primaryA := &Auth{
		ID:       "cred-a.json",
		Provider: "gemini-cli",
		Disabled: true,
		Status:   StatusDisabled,
		Attributes: map[string]string{
			"gemini_virtual_primary": "true",
			"path":                   "/auth/cred-a.json",
		},
		Metadata: map[string]any{"email": "a@example.com"},
	}
	badChild := &Auth{
		ID:       "cred-a.json::proj-a1",
		Provider: "gemini-cli",
		Attributes: map[string]string{
			"runtime_only":           "true",
			"gemini_virtual_parent":  primaryA.ID,
			"gemini_virtual_project": "proj-a1",
			"path":                   "/auth/cred-a.json",
		},
		Metadata: map[string]any{"email": "a@example.com", "project_id": "proj-a1", "virtual": true},
	}
	siblingChild := &Auth{
		ID:       "cred-a.json::proj-a2",
		Provider: "gemini-cli",
		Attributes: map[string]string{
			"runtime_only":           "true",
			"gemini_virtual_parent":  primaryA.ID,
			"gemini_virtual_project": "proj-a2",
			"path":                   "/auth/cred-a.json",
		},
		Metadata: map[string]any{"email": "a@example.com", "project_id": "proj-a2", "virtual": true},
	}
	primaryB := &Auth{
		ID:       "cred-b.json",
		Provider: "gemini-cli",
		Disabled: true,
		Status:   StatusDisabled,
		Attributes: map[string]string{
			"gemini_virtual_primary": "true",
			"path":                   "/auth/cred-b.json",
		},
		Metadata: map[string]any{"email": "b@example.com"},
	}
	goodChild := &Auth{
		ID:       "cred-b.json::proj-b1",
		Provider: "gemini-cli",
		Attributes: map[string]string{
			"runtime_only":           "true",
			"gemini_virtual_parent":  primaryB.ID,
			"gemini_virtual_project": "proj-b1",
			"path":                   "/auth/cred-b.json",
		},
		Metadata: map[string]any{"email": "b@example.com", "project_id": "proj-b1", "virtual": true},
	}
	registerSchedulerModels(t, "gemini-cli", model, badChild.ID, siblingChild.ID, goodChild.ID)

	for _, auth := range []*Auth{primaryA, badChild, siblingChild, primaryB, goodChild} {
		if _, err := m.Register(context.Background(), auth); err != nil {
			t.Fatalf("register %s: %v", auth.ID, err)
		}
	}

	resp, err := m.Execute(context.Background(), []string{"gemini-cli"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("execute error = %v, want success", err)
	}
	if string(resp.Payload) != goodChild.ID {
		t.Fatalf("execute payload = %q, want %q", string(resp.Payload), goodChild.ID)
	}

	for _, removedID := range []string{primaryA.ID, badChild.ID, siblingChild.ID} {
		if _, ok := m.GetByID(removedID); ok {
			t.Fatalf("expected %s to be removed with its virtual group", removedID)
		}
	}
	if _, ok := m.GetByID(goodChild.ID); !ok {
		t.Fatalf("expected surviving auth %s to remain registered", goodChild.ID)
	}

	resp, err = m.Execute(context.Background(), []string{"gemini-cli"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("second execute error = %v, want success", err)
	}
	if string(resp.Payload) != goodChild.ID {
		t.Fatalf("second execute payload = %q, want %q", string(resp.Payload), goodChild.ID)
	}

	got := executor.ExecuteCalls()
	want := []string{badChild.ID, goodChild.ID, goodChild.ID}
	if len(got) != len(want) {
		t.Fatalf("execute calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("execute call %d auth = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestManager_MarkResult_RespectsAuthDisableCoolingOverride(t *testing.T) {
	prev := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(prev) })

	m := NewManager(nil, nil, nil)

	auth := &Auth{
		ID:       "auth-1",
		Provider: "claude",
		Metadata: map[string]any{
			"disable_cooling": true,
		},
	}
	if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	model := "test-model"
	m.MarkResult(context.Background(), Result{
		AuthID:   "auth-1",
		Provider: "claude",
		Model:    model,
		Success:  false,
		Error:    &Error{HTTPStatus: 500, Message: "boom"},
	})

	updated, ok := m.GetByID("auth-1")
	if !ok || updated == nil {
		t.Fatalf("expected auth to be present")
	}
	state := updated.ModelStates[model]
	if state == nil {
		t.Fatalf("expected model state to be present")
	}
	if !state.NextRetryAfter.IsZero() {
		t.Fatalf("expected NextRetryAfter to be zero when disable_cooling=true, got %v", state.NextRetryAfter)
	}
}
