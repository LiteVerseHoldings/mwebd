package mwebd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/ltcmweb/ltcd/wire"
	"github.com/ltcmweb/mwebd/proto"
)

const (
	defaultOutputPageLimit = 1000
	maxOutputPageLimit     = 5000
)

type PublicOutput struct {
	OutputID  string `json:"outputId"`
	RawOutput string `json:"rawOutput"`
	LeafIndex uint64 `json:"leafIndex"`
	Height    int32  `json:"height"`
	BlockTime uint32 `json:"blockTime"`
}

type PublicOutputsResponse struct {
	Outputs    []PublicOutput `json:"outputs"`
	NextCursor uint64         `json:"nextCursor"`
	HasMore    bool           `json:"hasMore"`
	TipHeight  int32          `json:"tipHeight"`
}

type PublicStatusResponse struct {
	Available   bool   `json:"available"`
	Synced      bool   `json:"synced"`
	Network     string `json:"network"`
	Message     string `json:"message"`
	Height      int32  `json:"height"`
	TipHeight   int32  `json:"tipHeight"`
	BlockTime   uint32 `json:"blockTime"`
	UtxosHeight int32  `json:"utxosHeight"`
}

func (s *Server) StartHTTPAddr(addr string) error {
	if addr == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/outputs", s.handleOutputs)
	mux.HandleFunc("/spent", s.handleSpent)

	server := &http.Server{
		Addr:              addr,
		Handler:           withCors(mux),
		ReadHeaderTimeout: 15 * time.Second,
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	s.httpServer = server
	go server.Serve(lis)
	return nil
}

func withCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp, err := s.Status(r.Context(), nil)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	payload := PublicStatusResponse{
		Available:   true,
		Synced:      resp.BlockHeaderHeight == resp.MwebHeaderHeight && resp.MwebHeaderHeight == resp.MwebUtxosHeight,
		Network:     s.cp.Name,
		Message:     "mwebd ready",
		Height:      resp.MwebHeaderHeight,
		TipHeight:   resp.BlockHeaderHeight,
		BlockTime:   resp.BlockTime,
		UtxosHeight: resp.MwebUtxosHeight,
	}

	writeJSON(w, payload)
}

func (s *Server) handleOutputs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cursor, err := parseUint64Param(r, "cursor", 0)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	limit, err := parseIntParam(r, "limit", defaultOutputPageLimit)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	page, err := s.ListPublicOutputs(cursor, limit)
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, page)
}

func (s *Server) handleSpent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	outputIDs := r.URL.Query()["output_id"]
	if len(outputIDs) == 0 {
		writeJSON(w, map[string][]string{"outputId": {}})
		return
	}

	resp, err := s.Spent(r.Context(), &proto.SpentRequest{OutputId: outputIDs})
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, resp)
}

func (s *Server) ListPublicOutputs(cursor uint64, limit int) (*PublicOutputsResponse, error) {
	if limit <= 0 {
		limit = defaultOutputPageLimit
	}
	if limit > maxOutputPageLimit {
		limit = maxOutputPageLimit
	}

	lfs, err := s.cs.MwebCoinDB.GetLeafset()
	if err != nil {
		return nil, err
	}

	leaves := make([]uint64, 0, limit)
	nextCursor := cursor
	for nextCursor < lfs.Size && len(leaves) < limit {
		if lfs.Contains(nextCursor) {
			leaves = append(leaves, nextCursor)
		}
		nextCursor++
	}

	if len(leaves) == 0 {
		status, err := s.Status(context.Background(), &proto.StatusRequest{})
		if err != nil {
			return nil, err
		}
		return &PublicOutputsResponse{
			Outputs:    []PublicOutput{},
			NextCursor: nextCursor,
			HasMore:    false,
			TipHeight:  status.BlockHeaderHeight,
		}, nil
	}

	utxos, err := s.cs.MwebCoinDB.FetchLeaves(leaves)
	if err != nil {
		return nil, err
	}

	outputs := make([]PublicOutput, 0, len(utxos))
	for i, utxo := range utxos {
		record, err := s.publicOutputFromUtxo(leaves[i], utxo)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, record)
	}

	status, err := s.Status(context.Background(), &proto.StatusRequest{})
	if err != nil {
		return nil, err
	}

	return &PublicOutputsResponse{
		Outputs:    outputs,
		NextCursor: nextCursor,
		HasMore:    nextCursor < lfs.Size,
		TipHeight:  status.BlockHeaderHeight,
	}, nil
}

func (s *Server) publicOutputFromUtxo(leaf uint64, utxo *wire.MwebNetUtxo) (PublicOutput, error) {
	var buf bytes.Buffer
	if err := utxo.Output.Serialize(&buf); err != nil {
		return PublicOutput{}, err
	}

	blockTime := uint32(0)
	if utxo.Height > 0 {
		header, err := s.cs.BlockHeaders.FetchHeaderByHeight(uint32(utxo.Height))
		if err == nil {
			blockTime = uint32(header.Timestamp.Unix())
		}
	}

	return PublicOutput{
		OutputID:  hex.EncodeToString(utxo.OutputId[:]),
		RawOutput: hex.EncodeToString(buf.Bytes()),
		LeafIndex: leaf,
		Height:    utxo.Height,
		BlockTime: blockTime,
	}, nil
}

func parseUint64Param(r *http.Request, key string, defaultValue uint64) (uint64, error) {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return defaultValue, nil
	}
	return strconv.ParseUint(raw, 10, 64)
}

func parseIntParam(r *http.Request, key string, defaultValue int) (int, error) {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return defaultValue, nil
	}
	return strconv.Atoi(raw)
}

func writeJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}
