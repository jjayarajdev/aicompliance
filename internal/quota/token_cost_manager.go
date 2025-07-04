package quota

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// TokenCostManager manages AI provider token costs and budget tracking
type TokenCostManager struct {
	redisClient   *redis.Client
	logger        *logrus.Logger
	config        *TokenCostConfig
	providerCosts map[string]*ProviderCostInfo
	budgetManager *BudgetManager
	analytics     *CostAnalytics
	mu            sync.RWMutex
	startTime     time.Time
}

// TokenCostConfig holds configuration for token cost management
type TokenCostConfig struct {
	RedisKeyPrefix       string        `json:"redis_key_prefix" yaml:"redis_key_prefix"`
	CostCacheTTL         time.Duration `json:"cost_cache_ttl" yaml:"cost_cache_ttl"`
	BudgetCheckInterval  time.Duration `json:"budget_check_interval" yaml:"budget_check_interval"`
	CostUpdateInterval   time.Duration `json:"cost_update_interval" yaml:"cost_update_interval"`
	EnableCostOptimization bool        `json:"enable_cost_optimization" yaml:"enable_cost_optimization"`
	DefaultCurrency      string        `json:"default_currency" yaml:"default_currency"`
	CostPrecision        int           `json:"cost_precision" yaml:"cost_precision"`
	AlertThresholds      *AlertThresholds `json:"alert_thresholds" yaml:"alert_thresholds"`
}

// AlertThresholds defines when to trigger cost alerts
type AlertThresholds struct {
	BudgetWarningPercent   float64 `json:"budget_warning_percent" yaml:"budget_warning_percent"`     // 80%
	BudgetCriticalPercent  float64 `json:"budget_critical_percent" yaml:"budget_critical_percent"`   // 90%
	DailySpendThreshold    float64 `json:"daily_spend_threshold" yaml:"daily_spend_threshold"`       // $100
	HourlySpendThreshold   float64 `json:"hourly_spend_threshold" yaml:"hourly_spend_threshold"`     // $50
	UnusualSpendMultiplier float64 `json:"unusual_spend_multiplier" yaml:"unusual_spend_multiplier"` // 3x normal
}

// ProviderCostInfo holds cost information for AI providers
type ProviderCostInfo struct {
	ProviderName    string                    `json:"provider_name"`
	Models          map[string]*ModelCostInfo `json:"models"`
	DefaultCurrency string                    `json:"default_currency"`
	LastUpdated     time.Time                 `json:"last_updated"`
	RateCardVersion string                    `json:"rate_card_version"`
}

// ModelCostInfo holds cost information for specific AI models
type ModelCostInfo struct {
	ModelName         string  `json:"model_name"`
	InputTokenCost    float64 `json:"input_token_cost"`     // Cost per 1K input tokens
	OutputTokenCost   float64 `json:"output_token_cost"`    // Cost per 1K output tokens
	Currency          string  `json:"currency"`
	EffectiveDate     time.Time `json:"effective_date"`
	Deprecated        bool    `json:"deprecated"`
	RecommendedModel  string  `json:"recommended_model,omitempty"`
}

// TokenUsageRecord represents a token usage event
type TokenUsageRecord struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	OrgID         string    `json:"org_id"`
	Provider      string    `json:"provider"`
	Model         string    `json:"model"`
	Endpoint      string    `json:"endpoint"`
	InputTokens   int64     `json:"input_tokens"`
	OutputTokens  int64     `json:"output_tokens"`
	TotalTokens   int64     `json:"total_tokens"`
	InputCost     float64   `json:"input_cost"`
	OutputCost    float64   `json:"output_cost"`
	TotalCost     float64   `json:"total_cost"`
	Currency      string    `json:"currency"`
	Timestamp     time.Time `json:"timestamp"`
	RequestID     string    `json:"request_id"`
	ResponseTime  time.Duration `json:"response_time"`
	CacheHit      bool      `json:"cache_hit"`
}

// CostSummary provides aggregated cost information
type CostSummary struct {
	Period          string            `json:"period"`
	StartTime       time.Time         `json:"start_time"`
	EndTime         time.Time         `json:"end_time"`
	TotalCost       float64           `json:"total_cost"`
	TotalTokens     int64             `json:"total_tokens"`
	CostByProvider  map[string]float64 `json:"cost_by_provider"`
	CostByModel     map[string]float64 `json:"cost_by_model"`
	CostByUser      map[string]float64 `json:"cost_by_user"`
	CostByOrg       map[string]float64 `json:"cost_by_org"`
	TokensByModel   map[string]int64  `json:"tokens_by_model"`
	RequestCount    int64             `json:"request_count"`
	Currency        string            `json:"currency"`
	AvgCostPerRequest float64         `json:"avg_cost_per_request"`
	AvgCostPerToken   float64         `json:"avg_cost_per_token"`
}

// BudgetManager handles budget allocation and monitoring
type BudgetManager struct {
	budgets      map[string]*Budget `json:"budgets"`
	alerts       map[string]*BudgetAlert `json:"alerts"`
	mu           sync.RWMutex
	redisClient  *redis.Client
	logger       *logrus.Logger
}

// Budget represents a cost budget for users/organizations
type Budget struct {
	ID              string               `json:"id"`
	Name            string               `json:"name"`
	UserID          string               `json:"user_id,omitempty"`
	OrgID           string               `json:"org_id,omitempty"`
	Amount          float64              `json:"amount"`
	Currency        string               `json:"currency"`
	Period          BudgetPeriod         `json:"period"`
	StartDate       time.Time            `json:"start_date"`
	EndDate         time.Time            `json:"end_date"`
	CurrentSpend    float64              `json:"current_spend"`
	Remaining       float64              `json:"remaining"`
	PercentUsed     float64              `json:"percent_used"`
	Status          BudgetStatus         `json:"status"`
	AlertThresholds []float64            `json:"alert_thresholds"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
	LastChecked     time.Time            `json:"last_checked"`
}

// BudgetPeriod defines budget time periods
type BudgetPeriod string

const (
	BudgetPeriodDaily   BudgetPeriod = "daily"
	BudgetPeriodWeekly  BudgetPeriod = "weekly"
	BudgetPeriodMonthly BudgetPeriod = "monthly"
	BudgetPeriodQuarterly BudgetPeriod = "quarterly"
	BudgetPeriodYearly  BudgetPeriod = "yearly"
)

// BudgetStatus represents the current budget status
type BudgetStatus string

const (
	BudgetStatusActive    BudgetStatus = "active"
	BudgetStatusExceeded  BudgetStatus = "exceeded"
	BudgetStatusWarning   BudgetStatus = "warning"
	BudgetStatusCritical  BudgetStatus = "critical"
	BudgetStatusExpired   BudgetStatus = "expired"
)

// BudgetAlert represents a budget threshold alert
type BudgetAlert struct {
	ID          string          `json:"id"`
	BudgetID    string          `json:"budget_id"`
	Threshold   float64         `json:"threshold"`
	Triggered   bool            `json:"triggered"`
	AlertType   AlertType       `json:"alert_type"`
	Message     string          `json:"message"`
	CreatedAt   time.Time       `json:"created_at"`
	TriggeredAt *time.Time      `json:"triggered_at,omitempty"`
}

// AlertType defines types of cost alerts
type AlertType string

const (
	AlertTypeWarning  AlertType = "warning"
	AlertTypeCritical AlertType = "critical"
	AlertTypeExceeded AlertType = "exceeded"
)

// CostAnalytics provides cost analysis and optimization recommendations
type CostAnalytics struct {
	metrics      *CostMetrics
	trends       *CostTrends
	optimization *CostOptimization
	mu           sync.RWMutex
}

// CostMetrics tracks detailed cost metrics
type CostMetrics struct {
	TotalSpend          float64            `json:"total_spend"`
	DailySpend          float64            `json:"daily_spend"`
	WeeklySpend         float64            `json:"weekly_spend"`
	MonthlySpend        float64            `json:"monthly_spend"`
	SpendByProvider     map[string]float64 `json:"spend_by_provider"`
	SpendByModel        map[string]float64 `json:"spend_by_model"`
	TokensPerDollar     map[string]float64 `json:"tokens_per_dollar"`
	CostEfficiency      float64            `json:"cost_efficiency"`
	WastedSpend         float64            `json:"wasted_spend"`
	LastUpdated         time.Time          `json:"last_updated"`
}

// CostTrends tracks spending trends for forecasting
type CostTrends struct {
	DailyTrend     []float64 `json:"daily_trend"`     // Last 30 days
	WeeklyTrend    []float64 `json:"weekly_trend"`    // Last 12 weeks
	MonthlyTrend   []float64 `json:"monthly_trend"`   // Last 12 months
	GrowthRate     float64   `json:"growth_rate"`     // Month-over-month
	Seasonality    map[string]float64 `json:"seasonality"` // Seasonal patterns
	Forecast       *CostForecast `json:"forecast"`
}

// CostForecast provides spending predictions
type CostForecast struct {
	NextDay     float64 `json:"next_day"`
	NextWeek    float64 `json:"next_week"`
	NextMonth   float64 `json:"next_month"`
	Confidence  float64 `json:"confidence"`
	LastUpdated time.Time `json:"last_updated"`
}

// CostOptimization provides cost saving recommendations
type CostOptimization struct {
	Recommendations []CostRecommendation `json:"recommendations"`
	PotentialSavings float64            `json:"potential_savings"`
	LastAnalysis     time.Time          `json:"last_analysis"`
}

// CostRecommendation represents a cost optimization suggestion
type CostRecommendation struct {
	ID           string                 `json:"id"`
	Type         RecommendationType     `json:"type"`
	Title        string                 `json:"title"`
	Description  string                 `json:"description"`
	Impact       ImpactLevel           `json:"impact"`
	Effort       EffortLevel           `json:"effort"`
	Savings      float64               `json:"estimated_savings"`
	Details      map[string]interface{} `json:"details"`
	CreatedAt    time.Time             `json:"created_at"`
}

// RecommendationType defines types of cost optimization recommendations
type RecommendationType string

const (
	RecommendationModelSwitch    RecommendationType = "model_switch"
	RecommendationCaching        RecommendationType = "caching"
	RecommendationBatching       RecommendationType = "batching"
	RecommendationPromptOpt      RecommendationType = "prompt_optimization"
	RecommendationUsagePatterns  RecommendationType = "usage_patterns"
	RecommendationBudgetAdjust   RecommendationType = "budget_adjustment"
)

// ImpactLevel represents the potential impact of a recommendation
type ImpactLevel string

const (
	ImpactLow    ImpactLevel = "low"
	ImpactMedium ImpactLevel = "medium"
	ImpactHigh   ImpactLevel = "high"
)

// EffortLevel represents the effort required to implement a recommendation
type EffortLevel string

const (
	EffortLow    EffortLevel = "low"
	EffortMedium EffortLevel = "medium"
	EffortHigh   EffortLevel = "high"
)

// NewTokenCostManager creates a new token cost manager
func NewTokenCostManager(redisClient *redis.Client, logger *logrus.Logger, config *TokenCostConfig) (*TokenCostManager, error) {
	if config == nil {
		config = getDefaultTokenCostConfig()
	}

	if logger == nil {
		logger = logrus.New()
	}

	tcm := &TokenCostManager{
		redisClient:   redisClient,
		logger:        logger,
		config:        config,
		providerCosts: make(map[string]*ProviderCostInfo),
		startTime:     time.Now(),
	}

	// Initialize budget manager
	budgetManager := &BudgetManager{
		budgets:     make(map[string]*Budget),
		alerts:      make(map[string]*BudgetAlert),
		redisClient: redisClient,
		logger:      logger,
	}
	tcm.budgetManager = budgetManager

	// Initialize cost analytics
	analytics := &CostAnalytics{
		metrics: &CostMetrics{
			SpendByProvider: make(map[string]float64),
			SpendByModel:    make(map[string]float64),
			TokensPerDollar: make(map[string]float64),
		},
		trends: &CostTrends{
			Seasonality: make(map[string]float64),
		},
		optimization: &CostOptimization{
			Recommendations: []CostRecommendation{},
		},
	}
	tcm.analytics = analytics

	// Load provider cost information
	if err := tcm.loadProviderCosts(); err != nil {
		return nil, fmt.Errorf("failed to load provider costs: %w", err)
	}

	// Start background workers
	go tcm.startBudgetMonitor()
	go tcm.startCostAnalytics()

	logger.WithFields(logrus.Fields{
		"redis_prefix":     config.RedisKeyPrefix,
		"cache_ttl":        config.CostCacheTTL,
		"budget_interval":  config.BudgetCheckInterval,
		"cost_interval":    config.CostUpdateInterval,
		"currency":         config.DefaultCurrency,
	}).Info("Token cost manager initialized")

	return tcm, nil
}

// RecordTokenUsage records token usage and calculates costs
func (tcm *TokenCostManager) RecordTokenUsage(ctx context.Context, usage *TokenUsageRecord) error {
	startTime := time.Now()

	// Calculate costs
	if err := tcm.calculateCosts(usage); err != nil {
		tcm.logger.WithError(err).Error("Failed to calculate token costs")
		return err
	}

	// Store usage record
	if err := tcm.storeUsageRecord(ctx, usage); err != nil {
		tcm.logger.WithError(err).Error("Failed to store usage record")
		return err
	}

	// Update real-time metrics
	tcm.updateRealTimeMetrics(usage)

	// Check budget limits
	if err := tcm.checkBudgetLimits(ctx, usage); err != nil {
		tcm.logger.WithError(err).Warn("Budget limit check failed")
	}

	tcm.logger.WithFields(logrus.Fields{
		"user_id":      usage.UserID,
		"org_id":       usage.OrgID,
		"provider":     usage.Provider,
		"model":        usage.Model,
		"total_tokens": usage.TotalTokens,
		"total_cost":   usage.TotalCost,
		"currency":     usage.Currency,
		"duration":     time.Since(startTime),
	}).Debug("Token usage recorded")

	return nil
}

// calculateCosts calculates the cost for token usage
func (tcm *TokenCostManager) calculateCosts(usage *TokenUsageRecord) error {
	tcm.mu.RLock()
	providerInfo, exists := tcm.providerCosts[usage.Provider]
	tcm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("provider cost info not found: %s", usage.Provider)
	}

	modelInfo, exists := providerInfo.Models[usage.Model]
	if !exists {
		return fmt.Errorf("model cost info not found: %s/%s", usage.Provider, usage.Model)
	}

	// Calculate costs (rates are per 1K tokens)
	usage.InputCost = float64(usage.InputTokens) / 1000.0 * modelInfo.InputTokenCost
	usage.OutputCost = float64(usage.OutputTokens) / 1000.0 * modelInfo.OutputTokenCost
	usage.TotalCost = usage.InputCost + usage.OutputCost
	usage.Currency = modelInfo.Currency

	// Round to configured precision
	precision := tcm.config.CostPrecision
	usage.InputCost = math.Round(usage.InputCost*math.Pow10(precision)) / math.Pow10(precision)
	usage.OutputCost = math.Round(usage.OutputCost*math.Pow10(precision)) / math.Pow10(precision)
	usage.TotalCost = math.Round(usage.TotalCost*math.Pow10(precision)) / math.Pow10(precision)

	return nil
}

// GetUserCostSummary retrieves cost summary for a user
func (tcm *TokenCostManager) GetUserCostSummary(ctx context.Context, userID string, period string) (*CostSummary, error) {
	startTime, endTime := tcm.getPeriodRange(period)

	pattern := fmt.Sprintf("%susage:user:%s:*", tcm.config.RedisKeyPrefix, userID)
	keys, err := tcm.redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get usage keys: %w", err)
	}

	summary := &CostSummary{
		Period:         period,
		StartTime:      startTime,
		EndTime:        endTime,
		CostByProvider: make(map[string]float64),
		CostByModel:    make(map[string]float64),
		CostByUser:     make(map[string]float64),
		CostByOrg:      make(map[string]float64),
		TokensByModel:  make(map[string]int64),
		Currency:       tcm.config.DefaultCurrency,
	}

	for _, key := range keys {
		data, err := tcm.redisClient.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var usage TokenUsageRecord
		if err := json.Unmarshal([]byte(data), &usage); err != nil {
			continue
		}

		if usage.Timestamp.Before(startTime) || usage.Timestamp.After(endTime) {
			continue
		}

		// Aggregate data
		summary.TotalCost += usage.TotalCost
		summary.TotalTokens += usage.TotalTokens
		summary.RequestCount++
		summary.CostByProvider[usage.Provider] += usage.TotalCost
		summary.CostByModel[usage.Model] += usage.TotalCost
		summary.TokensByModel[usage.Model] += usage.TotalTokens
	}

	// Calculate averages
	if summary.RequestCount > 0 {
		summary.AvgCostPerRequest = summary.TotalCost / float64(summary.RequestCount)
	}
	if summary.TotalTokens > 0 {
		summary.AvgCostPerToken = summary.TotalCost / float64(summary.TotalTokens) * 1000.0 // Per 1K tokens
	}

	return summary, nil
}

// GetCostForecast generates cost forecasting based on historical data
func (tcm *TokenCostManager) GetCostForecast(ctx context.Context, userID, orgID string, days int) (*CostForecast, error) {
	// Get historical spending data
	var dailySpend []float64
	now := time.Now()

	for i := days; i > 0; i-- {
		date := now.AddDate(0, 0, -i)
		summary, err := tcm.GetUserCostSummary(ctx, userID, "daily")
		if err != nil {
			continue
		}
		dailySpend = append(dailySpend, summary.TotalCost)
	}

	if len(dailySpend) < 7 {
		return nil, fmt.Errorf("insufficient historical data for forecasting")
	}

	// Simple moving average forecasting
	recentDays := 7
	if len(dailySpend) < recentDays {
		recentDays = len(dailySpend)
	}

	recentAvg := 0.0
	for i := len(dailySpend) - recentDays; i < len(dailySpend); i++ {
		recentAvg += dailySpend[i]
	}
	recentAvg /= float64(recentDays)

	// Calculate trend
	trend := 0.0
	if len(dailySpend) >= 14 {
		firstHalf := 0.0
		secondHalf := 0.0
		midpoint := len(dailySpend) / 2

		for i := 0; i < midpoint; i++ {
			firstHalf += dailySpend[i]
		}
		for i := midpoint; i < len(dailySpend); i++ {
			secondHalf += dailySpend[i]
		}

		firstHalf /= float64(midpoint)
		secondHalf /= float64(len(dailySpend) - midpoint)
		trend = (secondHalf - firstHalf) / firstHalf
	}

	// Apply trend to forecast
	nextDayForecast := recentAvg * (1 + trend)
	nextWeekForecast := nextDayForecast * 7
	nextMonthForecast := nextDayForecast * 30

	// Calculate confidence based on data variability
	variance := 0.0
	for i := len(dailySpend) - recentDays; i < len(dailySpend); i++ {
		diff := dailySpend[i] - recentAvg
		variance += diff * diff
	}
	variance /= float64(recentDays)
	stdDev := math.Sqrt(variance)
	confidence := math.Max(0.1, 1.0-stdDev/recentAvg)

	return &CostForecast{
		NextDay:     nextDayForecast,
		NextWeek:    nextWeekForecast,
		NextMonth:   nextMonthForecast,
		Confidence:  confidence,
		LastUpdated: time.Now(),
	}, nil
}

// GetCostOptimizationRecommendations generates cost optimization recommendations
func (tcm *TokenCostManager) GetCostOptimizationRecommendations(ctx context.Context, userID string) ([]CostRecommendation, error) {
	var recommendations []CostRecommendation

	// Get user's recent usage patterns
	summary, err := tcm.GetUserCostSummary(ctx, userID, "monthly")
	if err != nil {
		return nil, err
	}

	// Model switching recommendations
	for model, cost := range summary.CostByModel {
		if cost > 50 { // Threshold for expensive models
			rec := CostRecommendation{
				ID:          fmt.Sprintf("model_switch_%s_%d", model, time.Now().Unix()),
				Type:        RecommendationModelSwitch,
				Title:       fmt.Sprintf("Consider switching from %s to a more cost-effective model", model),
				Description: fmt.Sprintf("You spent $%.2f on %s this month. Switching to a similar but cheaper model could save 20-40%%.", cost, model),
				Impact:      ImpactMedium,
				Effort:      EffortLow,
				Savings:     cost * 0.3, // Estimated 30% savings
				Details: map[string]interface{}{
					"current_model":      model,
					"current_cost":       cost,
					"recommended_models": []string{"gpt-3.5-turbo", "claude-instant"},
				},
				CreatedAt: time.Now(),
			}
			recommendations = append(recommendations, rec)
		}
	}

	// Caching recommendations
	if summary.RequestCount > 1000 {
		rec := CostRecommendation{
			ID:          fmt.Sprintf("caching_%s_%d", userID, time.Now().Unix()),
			Type:        RecommendationCaching,
			Title:       "Enable response caching to reduce API calls",
			Description: fmt.Sprintf("With %d requests this month, implementing caching could reduce costs by 15-25%%.", summary.RequestCount),
			Impact:      ImpactHigh,
			Effort:      EffortMedium,
			Savings:     summary.TotalCost * 0.2,
			Details: map[string]interface{}{
				"request_count":     summary.RequestCount,
				"cache_hit_potential": 0.2,
			},
			CreatedAt: time.Now(),
		}
		recommendations = append(recommendations, rec)
	}

	// Budget adjustment recommendations
	if summary.TotalCost > 500 {
		rec := CostRecommendation{
			ID:          fmt.Sprintf("budget_%s_%d", userID, time.Now().Unix()),
			Type:        RecommendationBudgetAdjust,
			Title:       "Set up budget alerts to monitor spending",
			Description: fmt.Sprintf("Your monthly spend of $%.2f suggests setting up budget alerts at $%.2f (80%%) and $%.2f (90%%).", summary.TotalCost, summary.TotalCost*0.8, summary.TotalCost*0.9),
			Impact:      ImpactLow,
			Effort:      EffortLow,
			Savings:     0,
			Details: map[string]interface{}{
				"current_spend":    summary.TotalCost,
				"suggested_budget": summary.TotalCost * 1.2,
			},
			CreatedAt: time.Now(),
		}
		recommendations = append(recommendations, rec)
	}

	// Sort by potential savings
	sort.Slice(recommendations, func(i, j int) bool {
		return recommendations[i].Savings > recommendations[j].Savings
	})

	return recommendations, nil
}

// Helper methods

func (tcm *TokenCostManager) loadProviderCosts() error {
	// Load OpenAI costs
	openai := &ProviderCostInfo{
		ProviderName:    "openai",
		DefaultCurrency: "USD",
		Models: map[string]*ModelCostInfo{
			"gpt-4": {
				ModelName:       "gpt-4",
				InputTokenCost:  0.03,   // $0.03 per 1K tokens
				OutputTokenCost: 0.06,   // $0.06 per 1K tokens
				Currency:        "USD",
				EffectiveDate:   time.Now().AddDate(0, -1, 0),
			},
			"gpt-4-turbo": {
				ModelName:       "gpt-4-turbo",
				InputTokenCost:  0.01,
				OutputTokenCost: 0.03,
				Currency:        "USD",
				EffectiveDate:   time.Now().AddDate(0, -1, 0),
			},
			"gpt-3.5-turbo": {
				ModelName:       "gpt-3.5-turbo",
				InputTokenCost:  0.001,
				OutputTokenCost: 0.002,
				Currency:        "USD",
				EffectiveDate:   time.Now().AddDate(0, -1, 0),
			},
		},
		LastUpdated:     time.Now(),
		RateCardVersion: "2024-01",
	}

	// Load Anthropic costs
	anthropic := &ProviderCostInfo{
		ProviderName:    "anthropic",
		DefaultCurrency: "USD",
		Models: map[string]*ModelCostInfo{
			"claude-3-opus": {
				ModelName:       "claude-3-opus",
				InputTokenCost:  0.015,
				OutputTokenCost: 0.075,
				Currency:        "USD",
				EffectiveDate:   time.Now().AddDate(0, -1, 0),
			},
			"claude-3-sonnet": {
				ModelName:       "claude-3-sonnet",
				InputTokenCost:  0.003,
				OutputTokenCost: 0.015,
				Currency:        "USD",
				EffectiveDate:   time.Now().AddDate(0, -1, 0),
			},
			"claude-instant": {
				ModelName:       "claude-instant",
				InputTokenCost:  0.0008,
				OutputTokenCost: 0.0024,
				Currency:        "USD",
				EffectiveDate:   time.Now().AddDate(0, -1, 0),
			},
		},
		LastUpdated:     time.Now(),
		RateCardVersion: "2024-01",
	}

	tcm.mu.Lock()
	tcm.providerCosts["openai"] = openai
	tcm.providerCosts["anthropic"] = anthropic
	tcm.mu.Unlock()

	return nil
}

func (tcm *TokenCostManager) storeUsageRecord(ctx context.Context, usage *TokenUsageRecord) error {
	key := fmt.Sprintf("%susage:user:%s:%d", tcm.config.RedisKeyPrefix, usage.UserID, usage.Timestamp.Unix())
	
	data, err := json.Marshal(usage)
	if err != nil {
		return fmt.Errorf("failed to marshal usage record: %w", err)
	}

	err = tcm.redisClient.Set(ctx, key, data, tcm.config.CostCacheTTL).Err()
	if err != nil {
		return fmt.Errorf("failed to store usage record: %w", err)
	}

	return nil
}

func (tcm *TokenCostManager) updateRealTimeMetrics(usage *TokenUsageRecord) {
	tcm.analytics.mu.Lock()
	defer tcm.analytics.mu.Unlock()

	metrics := tcm.analytics.metrics
	metrics.TotalSpend += usage.TotalCost
	metrics.SpendByProvider[usage.Provider] += usage.TotalCost
	metrics.SpendByModel[usage.Model] += usage.TotalCost
	metrics.LastUpdated = time.Now()
}

func (tcm *TokenCostManager) checkBudgetLimits(ctx context.Context, usage *TokenUsageRecord) error {
	// This would check user and org budgets and trigger alerts
	// Implementation would integrate with the budget manager
	return nil
}

func (tcm *TokenCostManager) getPeriodRange(period string) (time.Time, time.Time) {
	now := time.Now()
	switch period {
	case "daily":
		start := now.Truncate(24 * time.Hour)
		return start, start.Add(24 * time.Hour)
	case "weekly":
		start := now.AddDate(0, 0, -int(now.Weekday())).Truncate(24 * time.Hour)
		return start, start.AddDate(0, 0, 7)
	case "monthly":
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		return start, start.AddDate(0, 1, 0)
	default:
		start := now.Truncate(24 * time.Hour)
		return start, start.Add(24 * time.Hour)
	}
}

func (tcm *TokenCostManager) startBudgetMonitor() {
	ticker := time.NewTicker(tcm.config.BudgetCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		// Monitor budgets and trigger alerts
		tcm.logger.Debug("Budget monitoring check")
	}
}

func (tcm *TokenCostManager) startCostAnalytics() {
	ticker := time.NewTicker(tcm.config.CostUpdateInterval)
	defer ticker.Stop()

	for range ticker.C {
		// Update cost analytics and trends
		tcm.logger.Debug("Cost analytics update")
	}
}

func getDefaultTokenCostConfig() *TokenCostConfig {
	return &TokenCostConfig{
		RedisKeyPrefix:         "ai_gateway:token_cost:",
		CostCacheTTL:           24 * time.Hour,
		BudgetCheckInterval:    5 * time.Minute,
		CostUpdateInterval:     15 * time.Minute,
		EnableCostOptimization: true,
		DefaultCurrency:        "USD",
		CostPrecision:          4,
		AlertThresholds: &AlertThresholds{
			BudgetWarningPercent:   80.0,
			BudgetCriticalPercent:  90.0,
			DailySpendThreshold:    100.0,
			HourlySpendThreshold:   50.0,
			UnusualSpendMultiplier: 3.0,
		},
	}
} 