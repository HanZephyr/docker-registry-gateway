package gateway

import "net/http"

// LimitRequests protects the HTTP surface from unbounded concurrent work.
// Blob streams additionally hold the stricter pull-stream reservation owned by
// Switcher, while manifests and pings only consume this request-level budget.
func LimitRequests(next http.Handler, maximum int) http.Handler {
	if maximum <= 0 {
		return next
	}
	slots := make(chan struct{}, maximum)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			next.ServeHTTP(response, request)
		default:
			response.Header().Set("Retry-After", "1")
			http.Error(response, "gateway request capacity is exhausted", http.StatusServiceUnavailable)
		}
	})
}
