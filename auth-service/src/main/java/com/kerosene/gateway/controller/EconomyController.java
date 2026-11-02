package com.kerosene.gateway.controller;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.kerosene.common.dto.ApiResponse;
import com.kerosene.platform.market.BtcPriceQuoteBuilder;
import com.kerosene.platform.market.TickerService;

import java.util.HashMap;
import java.util.Map;

/**
 * Platform economy and market status endpoints.
 *
 * Financial execution, balances, wallets and transaction ownership remain inside KFE.
 */
@RestController
@RequestMapping("/api/economy")
public class EconomyController {

    /** Reads operational economy flags published in Redis. */
    private final StringRedisTemplate redisTemplate;
    /** Supplies current BTC market data for public quote responses. */
    private final TickerService tickerService;

    /** Creates economy endpoints with live operational and market-data providers.
     * @param redisTemplate reads current economy status values from Redis
     * @param tickerService supplies market prices and 24-hour changes
     */
    public EconomyController(StringRedisTemplate redisTemplate, TickerService tickerService) {
        this.redisTemplate = redisTemplate;
        this.tickerService = tickerService;
    }

    /** Returns current withdrawal fee and availability values, using product defaults when absent.
     * @return successful API envelope containing fee in satoshis and withdrawal status
     */
    @GetMapping("/status")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getEconomyStatus() {
        String fee = redisTemplate.opsForValue().get("economy:current_withdrawal_fee");
        String status = redisTemplate.opsForValue().get("system:status:withdrawals");

        Map<String, Object> data = new HashMap<>();
        data.put("withdrawalFeeSats", fee != null ? Long.parseLong(fee) : 10000L);
        data.put("withdrawalStatus", status != null ? status : "ENABLED");

        return ResponseEntity.ok(ApiResponse.success(
                "Current platform liquidity and economy status retrieved.",
                data));
    }

    /** Returns the current BTC quote currencies and metadata from the configured ticker service.
     * @return successful API envelope with prices, derived USD/BRL rate, and update timestamp
     */
    @GetMapping("/btc-price")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getBtcPrice() {
        Map<String, Object> data = BtcPriceQuoteBuilder.build(tickerService);
        return ResponseEntity.ok(ApiResponse.success(
                "Current BTC market prices retrieved.",
                data));
    }
}
