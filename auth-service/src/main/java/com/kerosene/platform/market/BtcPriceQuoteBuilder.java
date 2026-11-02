package com.kerosene.platform.market;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Shared BTC quote map for HTTP {@code /api/economy/btc-price} and STOMP
 * {@code /topic/btc-price}.
 */
public final class BtcPriceQuoteBuilder {

    /** Prevents instantiation of this stateless quote factory. */
    private BtcPriceQuoteBuilder() {}

    /** Builds the shared HTTP/STOMP quote map from the ticker service's current cached values.
     * @param tickerService source of prices and 24-hour USD change
     * @return quote map including BTC prices, derived USD/BRL rate, and generation time
     */
    public static Map<String, Object> build(TickerService tickerService) {
        BigDecimal btcUsd = tickerService.getPrice("usd");
        BigDecimal btcBrl = tickerService.getPrice("brl");
        BigDecimal btcEur = tickerService.getPrice("eur");
        BigDecimal usdBrl = BigDecimal.ZERO;

        if (btcUsd != null && btcUsd.compareTo(BigDecimal.ZERO) > 0
                && btcBrl != null) {
            usdBrl = btcBrl.divide(btcUsd, 8, RoundingMode.HALF_UP);
        }

        BigDecimal change24h = tickerService.getChange24hPercent("usd");

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("btcUsd", btcUsd);
        data.put("btcBrl", btcBrl);
        data.put("btcEur", btcEur);
        data.put("usdBrl", usdBrl);
        if (change24h != null) {
            data.put("btcUsdChange24hPercent", change24h);
        }
        data.put("updatedAt", Instant.now().toString());
        return data;
    }

    /** Builds the quote map directly from newly fetched market values before Redis persistence.
     * @param usd BTC price in US dollars
     * @param brl BTC price in Brazilian reais
     * @param eur BTC price in euros
     * @param usdChange24h BTC price change over 24 hours, or null when unavailable
     * @return quote map with the same field names as {@link #build(TickerService)}
     */
    public static Map<String, Object> buildFromFetched(
            BigDecimal usd,
            BigDecimal brl,
            BigDecimal eur,
            BigDecimal usdChange24h) {
        BigDecimal usdBrl = BigDecimal.ZERO;
        if (usd != null && usd.compareTo(BigDecimal.ZERO) > 0 && brl != null) {
            usdBrl = brl.divide(usd, 8, RoundingMode.HALF_UP);
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("btcUsd", usd);
        data.put("btcBrl", brl);
        data.put("btcEur", eur);
        data.put("usdBrl", usdBrl);
        if (usdChange24h != null) {
            data.put("btcUsdChange24hPercent", usdChange24h);
        }
        data.put("updatedAt", Instant.now().toString());
        return data;
    }
}
