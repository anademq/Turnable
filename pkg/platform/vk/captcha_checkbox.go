package vk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/theairblow/turnable/pkg/common"
)

// solveCheckboxCaptcha solves the checkbox captcha variant
func (V *Handler) solveCheckboxCaptcha(ctx context.Context, session *captchaSession) (string, error) {
	if err := V.captchaComponentDone(ctx, session); err != nil {
		return "", err
	}

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(time.Duration(400+rand.Intn(250)) * time.Millisecond):
	}

	cursor := "[]"

	check, err := V.performCaptchaCheck(ctx, session, "{}", cursor)
	if err != nil {
		return "", err
	}

	if check.ShowType != "" && !strings.EqualFold(check.ShowType, "checkbox") {
		return "", &captchaShowTypeError{ShowType: check.ShowType, Settings: check.Settings}
	}

	if strings.EqualFold(check.Status, "error_limit") {
		return "", errCaptchaRateLimit
	}

	if !strings.EqualFold(check.Status, "ok") {
		return "", fmt.Errorf("checkbox captcha rejected with status %s", check.Status)
	}

	if check.SuccessToken == "" {
		return "", errors.New("captcha success token not found")
	}

	return check.SuccessToken, nil
}

// captchaPowResult is the V2 proof-of-work captcha result
type captchaPowResult struct {
	Hash       string          `json:"hash"`
	Nonce      int             `json:"nonce"`
	DurationMs int64           `json:"duration_ms"`
	Telemetry  json.RawMessage `json:"telemetry"`
	TelHash    string          `json:"tel_hash"`
}

// buildCaptchaPoW solves the challenge and assembles the envelope submitted as the hash field
func (V *Handler) buildCaptchaPoW(page *captchaPage) (string, error) {
	hash, nonce := solveCaptchaPoW(page.PowInput, page.PowDifficulty)
	if hash == "" {
		return "", errors.New("no solution found")
	}

	telemetry, err := marshalCaptchaJSON(V.captchaTelemetry())
	if err != nil {
		return "", fmt.Errorf("failed to encode telemetry: %w", err)
	}

	telHash, err := hashCaptchaTelemetry(telemetry)
	if err != nil {
		return "", fmt.Errorf("failed to hash telemetry: %w", err)
	}

	envelope, err := marshalCaptchaJSON(captchaPowResult{
		Hash:       hash,
		Nonce:      nonce,
		DurationMs: captchaPowDuration(nonce),
		Telemetry:  telemetry,
		TelHash:    telHash,
	})
	if err != nil {
		return "", fmt.Errorf("failed to encode envelope: %w", err)
	}

	return "v2." + base64.StdEncoding.EncodeToString(envelope), nil
}

// solveCaptchaPoW brute-forces SHA-256 hash prefix target for PoW captcha
func solveCaptchaPoW(input string, difficulty int) (string, int) {
	if input == "" || difficulty <= 0 {
		return "", 0
	}

	target := strings.Repeat("0", difficulty)
	for nonce := 0; nonce <= 10_000_000; nonce++ {
		sum := sha256.Sum256([]byte(input + strconv.Itoa(nonce)))
		hash := hex.EncodeToString(sum[:])
		if strings.HasPrefix(hash, target) {
			return hash, nonce
		}
	}

	return "", 0
}

// captchaProbe wraps the result of a single telemetry probe
type captchaProbe struct {
	OK     bool `json:"ok"`
	Result any  `json:"result"`
}

// captchaTelemetry holds every probe the PoW script runs, in the order it runs them
type captchaTelemetry struct {
	Globals          captchaProbe `json:"globals"`
	UA               captchaProbe `json:"ua"`
	Frame            captchaProbe `json:"frame"`
	MatchMedia       captchaProbe `json:"match_media"`
	Plugins          captchaProbe `json:"plugins"`
	NavTamper        captchaProbe `json:"nav_tamper"`
	Referrer         captchaProbe `json:"referrer"`
	DevTools         captchaProbe `json:"devtools"`
	CSS              captchaProbe `json:"css"`
	NativeIntegrity  captchaProbe `json:"native_integrity"`
	CookieTest       captchaProbe `json:"cookie_test"`
	AncestorOrigins  captchaProbe `json:"ancestor_origins"`
	SandboxBehavior  captchaProbe `json:"sandbox_behavior"`
	MaxTouchPoints   captchaProbe `json:"max_touch_points"`
	TimezoneLocale   captchaProbe `json:"timezone_locale"`
	DevicePixelRatio captchaProbe `json:"device_pixel_ratio"`
}

// captchaGlobalsProbe reports which globals a browser is expected to expose
type captchaGlobalsProbe struct {
	Doc          bool `json:"doc"`
	Win          bool `json:"win"`
	Nav          bool `json:"nav"`
	Webdriver    bool `json:"webdriver"`
	Subtle       bool `json:"subtle"`
	Secure       bool `json:"secure"`
	GCS          bool `json:"gcs"`
	RAF          bool `json:"raf"`
	Wasm         bool `json:"wasm"`
	PluginsLen   int  `json:"plugins_len"`
	LanguagesLen int  `json:"languages_len"`
	HW           int  `json:"hw"`
	Mem          int  `json:"mem"`
}

// captchaUAProbe reports the user agent and its structured client hints counterpart
type captchaUAProbe struct {
	UserAgent     string              `json:"userAgent"`
	UserAgentData *captchaUADataProbe `json:"userAgentData"`
}

// captchaUADataProbe reports navigator.userAgentData
type captchaUADataProbe struct {
	Brands       []common.BrowserBrand `json:"brands"`
	Platform     string                `json:"platform"`
	Mobile       bool                  `json:"mobile"`
	Architecture *string               `json:"architecture"`
}

// captchaFrameProbe reports whether the captcha runs inside a frame
type captchaFrameProbe struct {
	FrameElement       *string `json:"frameElement"`
	AncestorOriginsLen int     `json:"ancestorOriginsLen"`
	ParentAccessible   bool    `json:"parentAccessible"`
}

// captchaMatchMediaProbe reports the media queries a browser resolves
type captchaMatchMediaProbe struct {
	PrefersDark   bool `json:"prefersDark"`
	PrefersLight  bool `json:"prefersLight"`
	ReducedMotion bool `json:"reducedMotion"`
	PointerFine   bool `json:"pointerFine"`
}

// captchaPluginsProbe reports navigator.plugins
type captchaPluginsProbe struct {
	Length       int        `json:"length"`
	Names        []string   `json:"names"`
	Descriptions []string   `json:"descriptions"`
	MimeTypes    [][]string `json:"mimeTypes"`
	IsChrome     bool       `json:"isChrome"`
}

// captchaNavTamperProbe reports whether anything has been patched over the DOM
type captchaNavTamperProbe struct {
	Tampered       bool   `json:"tampered"`
	ElCtor         string `json:"el_ctor"`
	StyleCtor      string `json:"style_ctor"`
	NavCtor        string `json:"nav_ctor"`
	AlertNative    bool   `json:"alert_native"`
	ToStringNative bool   `json:"to_string_native"`
}

// captchaReferrerProbe reports where the captcha page was navigated from
type captchaReferrerProbe struct {
	Referrer string `json:"referrer"`
	InIframe bool   `json:"inIframe"`
	Domain   string `json:"domain"`
}

// captchaDevToolsProbe reports whether developer tools are open
type captchaDevToolsProbe struct {
	Open    bool `json:"open"`
	DelayMs int  `json:"delay_ms"`
}

// captchaCSSProbe reports how many expected stylesheet rules are missing
type captchaCSSProbe struct {
	ExpectedMissing int `json:"expectedMissing"`
}

// captchaNativeIntegrityProbe reports whether builtins are still native code
type captchaNativeIntegrityProbe struct {
	ProtoMatch             bool `json:"protoMatch"`
	XHRNative              bool `json:"xhrNative"`
	XHRSendNative          bool `json:"xhrSendNative"`
	AddEventListenerNative bool `json:"addEventListenerNative"`
	AlertNative            bool `json:"alertNative"`
	ToStringNative         bool `json:"toStringNative"`
}

// captchaCookieTestProbe reports whether cookies can be written
type captchaCookieTestProbe struct {
	Write bool `json:"write"`
}

// captchaAncestorOriginsProbe reports the origin that embedded the captcha page
type captchaAncestorOriginsProbe struct {
	AncestorOrigin *string `json:"ancestorOrigin"`
}

// captchaSandboxBehaviorProbe reports whether the page runs sandboxed
type captchaSandboxBehaviorProbe struct {
	OriginIsNull   bool `json:"originIsNull"`
	LocalStorage   bool `json:"localStorage"`
	SessionStorage bool `json:"sessionStorage"`
}

// captchaMaxTouchPointsProbe reports the touch point count of the device
type captchaMaxTouchPointsProbe struct {
	MaxTouchPoints int `json:"maxTouchPoints"`
}

// captchaTimezoneLocaleProbe reports the timezone and languages of the device
type captchaTimezoneLocaleProbe struct {
	Timezone  string   `json:"timezone"`
	Languages []string `json:"languages"`
}

// captchaDevicePixelRatioProbe reports the pixel ratio and orientation of the screen
type captchaDevicePixelRatioProbe struct {
	DPR              float64 `json:"dpr"`
	Orientation      string  `json:"orientation"`
	OrientationAngle int     `json:"orientationAngle"`
}

// captchaPowDuration approximates how long a browser would have spent on the challenge.
func captchaPowDuration(nonce int) int64 {
	return max(int64(math.Round(float64(nonce+1)*0.015)), 1)
}

// hashCaptchaTelemetry generates the telemetry hash.
func hashCaptchaTelemetry(telemetry []byte) (string, error) {
	var decoded any
	if err := json.Unmarshal(telemetry, &decoded); err != nil {
		return "", err
	}

	canonical, err := marshalCaptchaJSON(decoded)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// marshalCaptchaJSON encodes a value the way JSON.stringify would, without HTML escaping
func marshalCaptchaJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}

	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// captchaProbeDone marks a probe as successfully collected
func captchaProbeDone(result any) captchaProbe {
	return captchaProbe{OK: true, Result: result}
}

// captchaTelemetry generates a plausible telemetry blob
func (V *Handler) captchaTelemetry() captchaTelemetry {
	profile := V.profile
	mobile := profile.IsMobile()
	plugins := captchaPlugins(profile)

	return captchaTelemetry{
		Globals: captchaProbeDone(captchaGlobalsProbe{
			Doc:          true,
			Win:          true,
			Nav:          true,
			Subtle:       true,
			Secure:       true,
			GCS:          true,
			RAF:          true,
			Wasm:         true,
			PluginsLen:   plugins.Length,
			LanguagesLen: len(common.BrowserLanguages),
			HW:           common.BrowserHardwareConcurrency,
			Mem:          common.BrowserDeviceMemory,
		}),
		UA: captchaProbeDone(captchaUAProbe{
			UserAgent: profile.UserAgent,
			UserAgentData: &captchaUADataProbe{
				Brands:   profile.Brands(),
				Platform: profile.PlatformName(),
				Mobile:   mobile,
			},
		}),
		Frame: captchaProbeDone(captchaFrameProbe{
			ParentAccessible: true,
		}),
		MatchMedia: captchaProbeDone(captchaMatchMediaProbe{
			PrefersLight: true,
			PointerFine:  !mobile,
		}),
		Plugins: captchaProbeDone(plugins),
		NavTamper: captchaProbeDone(captchaNavTamperProbe{
			ElCtor:         "HTMLDivElement",
			StyleCtor:      "CSSStyleDeclaration",
			NavCtor:        "Navigator",
			AlertNative:    true,
			ToStringNative: true,
		}),
		Referrer: captchaProbeDone(captchaReferrerProbe{
			Referrer: "https://" + captchaDomain + "/",
			Domain:   strings.TrimPrefix(captchaPageOrigin, "https://"),
		}),
		DevTools: captchaProbeDone(captchaDevToolsProbe{}),
		CSS:      captchaProbeDone(captchaCSSProbe{}),
		NativeIntegrity: captchaProbeDone(captchaNativeIntegrityProbe{
			ProtoMatch:             true,
			XHRNative:              true,
			XHRSendNative:          true,
			AddEventListenerNative: true,
			AlertNative:            true,
			ToStringNative:         true,
		}),
		CookieTest: captchaProbeDone(captchaCookieTestProbe{
			Write: true,
		}),
		AncestorOrigins: captchaProbeDone(captchaAncestorOriginsProbe{}),
		SandboxBehavior: captchaProbeDone(captchaSandboxBehaviorProbe{
			LocalStorage:   true,
			SessionStorage: true,
		}),
		MaxTouchPoints: captchaProbeDone(captchaMaxTouchPointsProbe{
			MaxTouchPoints: profile.MaxTouchPoints(),
		}),
		TimezoneLocale: captchaProbeDone(captchaTimezoneLocaleProbe{
			Timezone:  common.BrowserTimezone,
			Languages: common.BrowserLanguages,
		}),
		DevicePixelRatio: captchaProbeDone(captchaDevicePixelRatioProbe{
			DPR:         common.BrowserDevicePixelRatio,
			Orientation: profile.Orientation(),
		}),
	}
}

// captchaPlugins flattens the plugin list of a profile into the shape the probe reports it in
func captchaPlugins(profile common.BrowserProfile) captchaPluginsProbe {
	plugins := profile.Plugins()
	probe := captchaPluginsProbe{
		Length:       len(plugins),
		Names:        make([]string, len(plugins)),
		Descriptions: make([]string, len(plugins)),
		MimeTypes:    make([][]string, len(plugins)),
		IsChrome:     true,
	}

	for i, plugin := range plugins {
		probe.Names[i] = plugin.Name
		probe.Descriptions[i] = plugin.Description
		probe.MimeTypes[i] = plugin.MimeTypes
	}

	return probe
}
